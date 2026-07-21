// Package secretbox provides symmetric authenticated encryption (AES-256-GCM) for
// small secrets stored at rest (the CA signing key, SMTP/OIDC/LDAP credentials).
//
// New ciphertext uses a "v2" envelope whose key is derived with argon2id over a
// random per-record salt. Legacy ciphertext (written before the upgrade) used a
// bare SHA-256 of the passphrase with no salt; Open reads BOTH formats, so every
// existing sealed value keeps decrypting after the upgrade with no migration. New
// writes (settings re-saves, CA rotation, and an opportunistic CA re-seal) are v2.
package secretbox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/argon2"
)

// magic marks a v2 (argon2id) envelope: magic ‖ salt ‖ nonce ‖ ciphertext. The
// final byte is the format version. magicV3 marks a v3 (PBKDF2-HMAC-SHA256, FIPS)
// envelope with the same layout. A legacy blob (bare nonce ‖ ciphertext) has no
// such prefix. Open reads all three; Seal picks v2 or v3 per the active KDF.
var (
	magic   = []byte{0xF1, 0x33, 0x7B, 0x02}
	magicV3 = []byte{0xF1, 0x33, 0x7B, 0x03}
)

const saltLen = 16

// argon2id KEK parameters. The derivation runs once per seal/open; the secrets are
// small and opened infrequently (CA key at boot, credentials on read).
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
)

// pbkdf2Iterations is the PBKDF2-HMAC-SHA256 work factor for FIPS mode (SP 800-132);
// 600k matches current OWASP guidance for PBKDF2-SHA256.
const pbkdf2Iterations = 600_000

// useFIPS selects the KDF for NEW seals. It is set once at boot (SetFIPS) from
// FLEET_FIPS_MODE; default false keeps argon2id (v2) so non-FIPS installs are
// unchanged. Open always auto-detects the format, so both KDFs decrypt regardless.
var useFIPS bool

// SetFIPS selects PBKDF2 (FIPS) vs argon2id for subsequent seals. Call once at boot.
func SetFIPS(on bool) { useFIPS = on }

// SealBytes encrypts plaintext into a self-describing envelope (v3/PBKDF2 in FIPS
// mode, v2/argon2id otherwise).
func SealBytes(passphrase, plaintext []byte) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	prefix := magic
	key := argonKey(passphrase, salt)
	if useFIPS {
		prefix = magicV3
		k, err := pbkdf2Key(passphrase, salt)
		if err != nil {
			return nil, err
		}
		key = k
	}
	gcm, err := gcmFor(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{}, prefix...)
	out = append(out, salt...)
	out = append(out, nonce...)
	// gcm.Seal appends the ciphertext to out, giving prefix ‖ salt ‖ nonce ‖ ct.
	return gcm.Seal(out, nonce, plaintext, nil), nil
}

// OpenBytes reverses SealBytes and also decrypts v2 (argon2id) and legacy blobs —
// so a value sealed by any build (or the other KDF profile) keeps decrypting.
func OpenBytes(passphrase, raw []byte) ([]byte, error) {
	if bytes.HasPrefix(raw, magicV3) {
		if pt, err := openV3(passphrase, raw[len(magicV3):]); err == nil {
			return pt, nil
		}
	}
	if bytes.HasPrefix(raw, magic) {
		if pt, err := openV2(passphrase, raw[len(magic):]); err == nil {
			return pt, nil
		}
		// Astronomically unlikely: a legacy nonce that happens to start with magic.
		// Fall through and try the legacy scheme.
	}
	return openLegacy(passphrase, raw)
}

func openV3(passphrase, body []byte) ([]byte, error) {
	if len(body) < saltLen {
		return nil, errors.New("ciphertext too short")
	}
	salt, rest := body[:saltLen], body[saltLen:]
	key, err := pbkdf2Key(passphrase, salt)
	if err != nil {
		return nil, err
	}
	gcm, err := gcmFor(key)
	if err != nil {
		return nil, err
	}
	if len(rest) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := rest[:gcm.NonceSize()], rest[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

func pbkdf2Key(passphrase, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(passphrase), salt, pbkdf2Iterations, 32)
}

func openV2(passphrase, body []byte) ([]byte, error) {
	if len(body) < saltLen {
		return nil, errors.New("ciphertext too short")
	}
	salt, rest := body[:saltLen], body[saltLen:]
	gcm, err := gcmFor(argonKey(passphrase, salt))
	if err != nil {
		return nil, err
	}
	if len(rest) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := rest[:gcm.NonceSize()], rest[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

func openLegacy(passphrase, raw []byte) ([]byte, error) {
	key := sha256.Sum256(passphrase)
	gcm, err := gcmFor(key[:])
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// IsLegacy reports whether raw is an old (pre-v2) blob, so callers can
// opportunistically re-seal it in the current format.
func IsLegacy(raw []byte) bool {
	return !bytes.HasPrefix(raw, magic) && !bytes.HasPrefix(raw, magicV3)
}

// IsFIPSSealed reports whether raw uses the v3 (PBKDF2) envelope.
func IsFIPSSealed(raw []byte) bool { return bytes.HasPrefix(raw, magicV3) }

// NeedsReseal reports whether raw should be re-sealed to match the active KDF
// profile — legacy/v2 under FIPS, or (harmlessly) a v3 blob when FIPS is off. Used
// by the migration re-seal sweep.
func NeedsReseal(raw []byte) bool {
	if useFIPS {
		return !bytes.HasPrefix(raw, magicV3)
	}
	return IsLegacy(raw)
}

// ResealBytes re-seals a raw envelope to the active KDF profile if (and only if) it
// needs it, verifying the new envelope decrypts to the identical plaintext before
// returning it. It returns the (possibly unchanged) envelope and whether it changed.
// A value that already matches the active profile is returned untouched.
func ResealBytes(passphrase, raw []byte) (out []byte, changed bool, err error) {
	if !NeedsReseal(raw) {
		return raw, false, nil
	}
	plain, err := OpenBytes(passphrase, raw)
	if err != nil {
		return raw, false, err
	}
	sealed, err := SealBytes(passphrase, plain)
	if err != nil {
		return raw, false, err
	}
	// Verify-before-return: never hand back an envelope that doesn't round-trip.
	if check, oerr := OpenBytes(passphrase, sealed); oerr != nil || !bytes.Equal(check, plain) {
		return raw, false, errors.New("reseal verification failed")
	}
	return sealed, true, nil
}

// ResealString is ResealBytes over a base64 (Seal) value: returns the (possibly new)
// base64 string and whether it changed. An empty string is a no-op.
func ResealString(passphrase []byte, encoded string) (out string, changed bool, err error) {
	if encoded == "" {
		return encoded, false, nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return encoded, false, err
	}
	sealed, changed, err := ResealBytes(passphrase, raw)
	if err != nil || !changed {
		return encoded, false, err
	}
	return base64.StdEncoding.EncodeToString(sealed), true, nil
}

func argonKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, 32)
}

func gcmFor(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// Seal encrypts plaintext and returns a base64 string (v2 envelope).
func Seal(passphrase, plaintext []byte) (string, error) {
	raw, err := SealBytes(passphrase, plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// Open reverses Seal (and decrypts legacy base64 blobs).
func Open(passphrase []byte, encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return OpenBytes(passphrase, raw)
}
