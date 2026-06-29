package secretbox

import "testing"

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
