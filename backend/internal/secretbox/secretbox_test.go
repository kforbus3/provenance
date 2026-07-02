package secretbox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// legacySeal reproduces the exact pre-upgrade format (bare SHA-256 key, nonce‖ct,
// base64) so we can prove the new Open still decrypts data written by old builds.
func legacySeal(t *testing.T, passphrase, plaintext []byte) (raw []byte, b64 string) {
	t.Helper()
	key := sha256.Sum256(passphrase)
	blk, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(blk)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	raw = gcm.Seal(nonce, nonce, plaintext, nil)
	return raw, base64.StdEncoding.EncodeToString(raw)
}

func TestOpenDecryptsLegacyData(t *testing.T) {
	pass := []byte("the-original-ca-passphrase-123456")
	pt := []byte("-----BEGIN OPENSSH PRIVATE KEY----- ... crown jewel ...")

	rawLegacy, b64Legacy := legacySeal(t, pass, pt)

	// The whole point of H4: existing blobs must still decrypt after the upgrade.
	if got, err := OpenBytes(pass, rawLegacy); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("legacy OpenBytes failed: got=%q err=%v", got, err)
	}
	if got, err := Open(pass, b64Legacy); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("legacy Open failed: got=%q err=%v", got, err)
	}
	if !IsLegacy(rawLegacy) {
		t.Error("IsLegacy should be true for an old blob")
	}
}

func TestV2Envelope(t *testing.T) {
	pass := []byte("the-original-ca-passphrase-123456")
	pt := []byte("smtp-app-password")

	raw, err := SealBytes(pass, pt)
	if err != nil {
		t.Fatal(err)
	}
	if IsLegacy(raw) {
		t.Fatal("SealBytes must produce a v2 (non-legacy) envelope")
	}
	if got, err := OpenBytes(pass, raw); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("v2 round-trip failed: got=%q err=%v", got, err)
	}
	// Tampering is detected (GCM auth).
	raw[len(raw)-1] ^= 0xFF
	if _, err := OpenBytes(pass, raw); err == nil {
		t.Error("tampered ciphertext should fail authentication")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	pass := []byte("a-test-passphrase-at-least-16")
	secret := []byte("smtp-app-password")

	ct, err := Seal(pass, secret)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if ct == string(secret) {
		t.Fatal("ciphertext equals plaintext")
	}
	pt, err := Open(pass, ct)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(pt) != string(secret) {
		t.Fatalf("round-trip mismatch: got %q", pt)
	}
}

func TestOpenWrongPassphraseFails(t *testing.T) {
	ct, err := Seal([]byte("correct-passphrase-value"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open([]byte("wrong-passphrase-value!!"), ct); err == nil {
		t.Fatal("expected authentication failure with wrong passphrase")
	}
}

func TestOpenRejectsGarbage(t *testing.T) {
	if _, err := Open([]byte("pass"), "not-base64!!!"); err == nil {
		t.Fatal("expected error on invalid base64")
	}
	if _, err := Open([]byte("pass"), "AAAA"); err == nil {
		t.Fatal("expected error on too-short ciphertext")
	}
}
