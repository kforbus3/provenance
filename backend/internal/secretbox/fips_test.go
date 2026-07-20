package secretbox

import (
	"bytes"
	"testing"
)

func TestFIPSKDFRoundTripAndCrossOpen(t *testing.T) {
	pass := []byte("a-strong-passphrase")
	plain := []byte("the CA private key material")

	// v2 (argon2id) seal — default profile.
	SetFIPS(false)
	v2, err := SealBytes(pass, plain)
	if err != nil {
		t.Fatal(err)
	}
	if IsFIPSSealed(v2) {
		t.Error("default seal should not be FIPS-sealed")
	}

	// v3 (PBKDF2) seal — FIPS profile.
	SetFIPS(true)
	v3, err := SealBytes(pass, plain)
	if err != nil {
		t.Fatal(err)
	}
	if !IsFIPSSealed(v3) {
		t.Error("FIPS seal should be v3/PBKDF2")
	}
	if !NeedsReseal(v2) {
		t.Error("a v2 blob should need reseal under FIPS")
	}
	if NeedsReseal(v3) {
		t.Error("a v3 blob should not need reseal under FIPS")
	}

	// Open must decrypt BOTH regardless of the active profile (migration safety).
	for _, blob := range [][]byte{v2, v3} {
		got, err := OpenBytes(pass, blob)
		if err != nil {
			t.Fatalf("open failed: %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("round-trip mismatch: %q", got)
		}
	}

	// Reset to default so other tests in the package are unaffected.
	SetFIPS(false)
}

func TestResealBytesUpgradesV2ToV3(t *testing.T) {
	pass := []byte("a-strong-passphrase")
	plain := []byte("SMTP app password")

	SetFIPS(false)
	v2, err := SealBytes(pass, plain)
	if err != nil {
		t.Fatal(err)
	}
	defer SetFIPS(false)

	// Under FIPS, a v2 blob reseals to v3 and still decrypts to the same plaintext.
	SetFIPS(true)
	out, changed, err := ResealBytes(pass, v2)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("v2 under FIPS should have been re-sealed")
	}
	if !IsFIPSSealed(out) {
		t.Error("re-sealed blob should be v3/PBKDF2")
	}
	got, err := OpenBytes(pass, out)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("re-sealed blob does not round-trip: got=%q err=%v", got, err)
	}

	// Idempotent: a v3 blob under FIPS is left untouched.
	out2, changed2, err := ResealBytes(pass, out)
	if err != nil {
		t.Fatal(err)
	}
	if changed2 {
		t.Error("a v3 blob under FIPS should not be re-sealed again")
	}
	if !bytes.Equal(out2, out) {
		t.Error("no-op reseal must return the identical envelope")
	}
}

func TestResealStringRoundTrip(t *testing.T) {
	pass := []byte("a-strong-passphrase")
	defer SetFIPS(false)

	SetFIPS(false)
	enc, err := Seal(pass, []byte("client-secret-value"))
	if err != nil {
		t.Fatal(err)
	}

	SetFIPS(true)
	out, changed, err := ResealString(pass, enc)
	if err != nil || !changed {
		t.Fatalf("expected reseal: changed=%v err=%v", changed, err)
	}
	got, err := Open(pass, out)
	if err != nil || string(got) != "client-secret-value" {
		t.Fatalf("re-sealed string mismatch: got=%q err=%v", got, err)
	}

	// Empty string is a no-op, never an error.
	if o, c, e := ResealString(pass, ""); o != "" || c || e != nil {
		t.Errorf("empty reseal should be a clean no-op, got %q %v %v", o, c, e)
	}
}
