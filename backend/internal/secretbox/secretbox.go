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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/argon2"
)

// magic marks a v2 envelope: magic ‖ salt ‖ nonce ‖ ciphertext. The final byte is
// the format version. A legacy blob (bare nonce ‖ ciphertext) has no such prefix.
var magic = []byte{0xF1, 0x33, 0x7B, 0x02}

const saltLen = 16

// argon2id KEK parameters. The derivation runs once per seal/open; the secrets are
// small and opened infrequently (CA key at boot, credentials on read).
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
)

// SealBytes encrypts plaintext into a self-describing v2 envelope.
func SealBytes(passphrase, plaintext []byte) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	gcm, err := gcmFor(argonKey(passphrase, salt))
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{}, magic...)
	out = append(out, salt...)
	out = append(out, nonce...)
	// gcm.Seal appends the ciphertext to out, giving magic ‖ salt ‖ nonce ‖ ct.
	return gcm.Seal(out, nonce, plaintext, nil), nil
}

// OpenBytes reverses SealBytes and also decrypts legacy (pre-upgrade) blobs.
func OpenBytes(passphrase, raw []byte) ([]byte, error) {
	if bytes.HasPrefix(raw, magic) {
		if pt, err := openV2(passphrase, raw[len(magic):]); err == nil {
			return pt, nil
		}
		// Astronomically unlikely: a legacy nonce that happens to start with magic.
		// Fall through and try the legacy scheme.
	}
	return openLegacy(passphrase, raw)
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

// IsLegacy reports whether raw is an old (pre-upgrade) blob, so callers can
// opportunistically re-seal it as v2.
func IsLegacy(raw []byte) bool { return !bytes.HasPrefix(raw, magic) }

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
