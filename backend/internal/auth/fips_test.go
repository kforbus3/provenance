package auth

import (
	"strings"
	"testing"
)

func TestPasswordFIPSHashingAndCrossVerify(t *testing.T) {
	const pw = "Correct-Horse-Battery-Staple-9"

	// Default profile → argon2id; verifies.
	SetPasswordFIPS(false)
	argonHash, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(argonHash, "$argon2id$") {
		t.Fatalf("default hash should be argon2id, got %q", argonHash[:12])
	}

	// FIPS profile → pbkdf2; verifies.
	SetPasswordFIPS(true)
	pbHash, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pbHash, "$pbkdf2-sha256$") {
		t.Fatalf("FIPS hash should be pbkdf2-sha256, got %q", pbHash)
	}

	// Both algorithms verify regardless of the active profile (verify-then-upgrade).
	for _, h := range []string{argonHash, pbHash} {
		ok, err := VerifyPassword(pw, h)
		if err != nil || !ok {
			t.Fatalf("verify failed for %.15s: ok=%v err=%v", h, ok, err)
		}
		if bad, _ := VerifyPassword("wrong", h); bad {
			t.Fatalf("verify accepted a wrong password for %.15s", h)
		}
	}

	// Under FIPS, an argon2id hash needs a rehash; a pbkdf2 one does not.
	if !PasswordNeedsRehash(argonHash) {
		t.Error("argon2id hash should need rehash under FIPS")
	}
	if PasswordNeedsRehash(pbHash) {
		t.Error("pbkdf2 hash should not need rehash under FIPS")
	}

	SetPasswordFIPS(false)
}
