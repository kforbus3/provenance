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
