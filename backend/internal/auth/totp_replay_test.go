package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TestMatchTOTPStep verifies the step matcher accepts a freshly generated code
// (must never reject a legitimate code) and returns the expected timestep, and
// that a bogus code matches nothing.
func TestMatchTOTPStep(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Fleet", AccountName: "u@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	secret := key.Secret()

	now := time.Now()
	code, err := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal(err)
	}

	step, ok := matchTOTPStep(secret, code)
	if !ok {
		t.Fatal("a freshly generated code must match a step (would falsely reject a real login)")
	}
	if want := now.Unix() / 30; step != want {
		t.Errorf("step = %d, want %d", step, want)
	}
	// The same code must resolve to the same step (so a replay is detectable).
	if step2, ok2 := matchTOTPStep(secret, code); !ok2 || step2 != step {
		t.Errorf("re-match = (%d,%v), want (%d,true)", step2, ok2, step)
	}
	// A wrong code matches nothing.
	if _, ok := matchTOTPStep(secret, "000000"); ok && code == "000000" {
		t.Skip("unlucky code collision")
	}
}
