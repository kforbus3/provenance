// Package secretbox provides symmetric authenticated encryption for small
// secrets stored at rest (e.g. SMTP/webhook credentials in the settings table).
// The key is derived from a passphrase with SHA-256; ciphertext is AES-256-GCM
// and returned base64-encoded so it can live in a JSON column. This mirrors the
// CA's at-rest scheme but is generic and reusable.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// Seal encrypts plaintext with a key derived from passphrase, returning a
// base64-encoded (nonce ‖ ciphertext) string.
func Seal(passphrase, plaintext []byte) (string, error) {
	gcm, err := newGCM(passphrase)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Open reverses Seal.
func Open(passphrase []byte, encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(passphrase)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

func newGCM(passphrase []byte) (cipher.AEAD, error) {
	key := sha256.Sum256(passphrase)
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}
