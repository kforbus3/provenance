// Package keys manages the Ed25519 identity keypairs used for multi-site
// federation. Both the hub (fed_hub_key) and each site hold one. Private keys are
// encrypted at rest with the same secretbox envelope + CA passphrase used for the
// SSH CA key, so no new secret material is introduced.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/fleet-terminal/backend/internal/secretbox"
)

// Identity is an Ed25519 keypair with its derived fingerprint.
type Identity struct {
	Public      ed25519.PublicKey
	Private     ed25519.PrivateKey
	Fingerprint string // "SHA256:<base64>" over the raw public key
}

// Generate creates a fresh federation identity.
func Generate() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return &Identity{Public: pub, Private: priv, Fingerprint: Fingerprint(pub)}, nil
}

// Fingerprint returns a stable "SHA256:<base64>" fingerprint of a public key,
// mirroring OpenSSH's key-fingerprint style so operators can pin/compare it.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// SealPrivate encrypts a private key for storage using the CA passphrase envelope.
func SealPrivate(passphrase []byte, priv ed25519.PrivateKey) ([]byte, error) {
	return secretbox.SealBytes(passphrase, priv)
}

// OpenPrivate decrypts a stored private key.
func OpenPrivate(passphrase, sealed []byte) (ed25519.PrivateKey, error) {
	raw, err := secretbox.OpenBytes(passphrase, sealed)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("federation: bad private key length %d", len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

// PublicFromBytes validates and wraps a stored public key.
func PublicFromBytes(b []byte) (ed25519.PublicKey, error) {
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("federation: bad public key length %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}
