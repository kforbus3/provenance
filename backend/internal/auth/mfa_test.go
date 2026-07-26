package auth

import (
	"testing"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/config"
)

func testService() *Service {
	cfg := &config.Config{}
	cfg.JWTSecret = []byte("unit-test-secret-at-least-32-bytes-long")
	return NewService(nil, cfg, nil)
}

func TestMFASecretEncryptionRoundTrip(t *testing.T) {
	s := testService()
	plain := "JBSWY3DPEHPK3PXP"
	enc, err := s.EncryptSecret(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(enc) == plain {
		t.Fatal("ciphertext must not equal plaintext")
	}
	got, err := s.DecryptSecret(enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != plain {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, plain)
	}
}

// TestMFAKeyMigration proves the backward-compat path that prevents an MFA lockout when
// a deployment adopts a dedicated FLEET_MFA_ENCRYPTION_KEY: a secret encrypted with only
// the JWT-derived key must still decrypt after the dedicated key is added, and new
// secrets must then use (and round-trip under) the dedicated key.
func TestMFAKeyMigration(t *testing.T) {
	jwt := []byte("unit-test-secret-at-least-32-bytes-long")

	// 1. Legacy service: no dedicated key. Encrypt a secret.
	legacy := NewService(nil, &config.Config{JWTSecret: jwt}, nil)
	plain := "JBSWY3DPEHPK3PXP"
	encLegacy, err := legacy.EncryptSecret(plain)
	if err != nil {
		t.Fatalf("legacy encrypt: %v", err)
	}

	// 2. Same deployment now sets a dedicated MFA key. The old secret must still decrypt
	//    (fallback to the JWT-derived key), or every enrolled user would be locked out.
	migrated := NewService(nil, &config.Config{
		JWTSecret:        jwt,
		MFAEncryptionKey: []byte("a-different-dedicated-mfa-key-32b!!"),
	}, nil)
	got, err := migrated.DecryptSecret(encLegacy)
	if err != nil || got != plain {
		t.Fatalf("legacy secret must still decrypt after adopting a dedicated key: got %q err %v", got, err)
	}

	// 3. A newly-encrypted secret round-trips under the dedicated key, and is NOT
	//    decryptable by the JWT secret alone (confirming decoupling).
	encNew, _ := migrated.EncryptSecret(plain)
	if got, err := migrated.DecryptSecret(encNew); err != nil || got != plain {
		t.Fatalf("new secret round-trip failed: got %q err %v", got, err)
	}
	if _, err := legacy.DecryptSecret(encNew); err == nil {
		t.Fatal("a secret written under the dedicated key should not decrypt with the JWT key alone")
	}
}

func TestMFASecretEncryptionUniqueNonce(t *testing.T) {
	s := testService()
	a, _ := s.EncryptSecret("same-secret")
	b, _ := s.EncryptSecret("same-secret")
	if string(a) == string(b) {
		t.Fatal("encryptions of the same secret must differ (random nonce)")
	}
}

func TestMFAChallengeRoundTrip(t *testing.T) {
	s := testService()
	uid := uuid.New()
	tok, err := s.IssueMFAChallenge(uid)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := s.ParseMFAChallenge(tok)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != uid {
		t.Fatalf("uid mismatch: %v != %v", got, uid)
	}
}

func TestMFAChallengeRejectsAccessToken(t *testing.T) {
	s := testService()
	// An access token must not be accepted as an MFA challenge (purpose differs).
	access, _ := IssueAccessToken(s.cfg.JWTSecret, uuid.New(), uuid.New(), "u", 60_000_000_000)
	if _, err := s.ParseMFAChallenge(access); err == nil {
		t.Fatal("access token must be rejected as an mfa challenge")
	}
}

func TestValidateTOTPRejectsGarbage(t *testing.T) {
	if ValidateTOTP("JBSWY3DPEHPK3PXP", "000000") && ValidateTOTP("JBSWY3DPEHPK3PXP", "abcdef") {
		t.Fatal("static wrong codes should not both validate")
	}
}
