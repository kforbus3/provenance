package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Sign produces a detached Ed25519 signature over the exact manifest bytes.
func Sign(manifestJSON []byte, priv ed25519.PrivateKey) []byte {
	return ed25519.Sign(priv, manifestJSON)
}

// Verify checks a detached signature over the manifest bytes against any of the
// trusted public keys. It succeeds on the first key that verifies. An empty trust set
// is a hard error — Fleet fails closed and applies nothing until a release key is
// configured.
func Verify(manifestJSON, sig []byte, trusted []ed25519.PublicKey) error {
	if len(trusted) == 0 {
		return errors.New("no trusted release keys configured; refusing to trust the bundle")
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature is not a valid Ed25519 signature (%d bytes)", len(sig))
	}
	for _, pub := range trusted {
		if len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, manifestJSON, sig) {
			return nil
		}
	}
	return errors.New("bundle signature does not match any trusted release key")
}

// GenerateKey returns a fresh Ed25519 release keypair.
func GenerateKey() (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	return ed25519.GenerateKey(rand.Reader)
}

// EncodePublicKey / EncodePrivateKey render keys as base64 (raw std, no padding) for
// storing in env/config or embedding at build time.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.RawStdEncoding.EncodeToString(pub)
}

func EncodePrivateKey(priv ed25519.PrivateKey) string {
	return base64.RawStdEncoding.EncodeToString(priv)
}

// EncodeSig renders a detached signature as base64 (raw std) for writing to a .sig
// file. FetchChannel's decodeSig accepts this or the raw bytes.
func EncodeSig(sig []byte) string {
	return base64.RawStdEncoding.EncodeToString(sig)
}

// ParsePublicKeys parses a comma- or whitespace-separated list of base64 Ed25519
// public keys (accepting both standard and raw/no-pad encodings). Blank entries are
// skipped; an all-blank input yields an empty slice with no error.
func ParsePublicKeys(s string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' }) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		b, err := decodeB64(tok)
		if err != nil {
			return nil, fmt.Errorf("invalid release public key: %w", err)
		}
		if len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release public key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
		}
		out = append(out, ed25519.PublicKey(b))
	}
	return out, nil
}

// ParsePrivateKey parses a base64 Ed25519 private key (raw std or std padding).
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := decodeB64(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("invalid release private key: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("release private key is %d bytes, want %d", len(b), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(b), nil
}

func decodeB64(s string) ([]byte, error) {
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}
