package kms

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSignV4GetVanilla checks the SigV4 implementation against AWS's published
// "get-vanilla" test vector (Signature Version 4 test suite). A byte-exact match on
// the Authorization header validates canonicalization, the string-to-sign, and the
// signing-key derivation without needing a live AWS account.
func TestSignV4GetVanilla(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	creds := awsCreds{
		accessKey: "AKIDEXAMPLE",
		secretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}
	when := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)

	signV4(req, nil, "us-east-1", "service", creds, when)

	want := "AWS4-HMAC-SHA256 " +
		"Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, " +
		"Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization mismatch:\n got: %s\nwant: %s", got, want)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20150830T123600Z" {
		t.Errorf("X-Amz-Date = %q, want 20150830T123600Z", got)
	}
}

// TestSignV4IncludesSessionToken verifies an STS session token is set and signed.
func TestSignV4IncludesSessionToken(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://kms.us-east-1.amazonaws.com/", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService.Encrypt")
	creds := awsCreds{accessKey: "AK", secretKey: "SK", sessionToken: "TOKEN123"}

	signV4(req, []byte("{}"), "us-east-1", "kms", creds, time.Unix(0, 0))

	if req.Header.Get("X-Amz-Security-Token") != "TOKEN123" {
		t.Error("session token header not set")
	}
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "x-amz-security-token") {
		t.Errorf("session token not in SignedHeaders: %s", auth)
	}
	// Content-Type and target must also be signed for a KMS POST.
	for _, h := range []string{"content-type", "x-amz-target", "host", "x-amz-date"} {
		if !strings.Contains(auth, h) {
			t.Errorf("expected %q in SignedHeaders: %s", h, auth)
		}
	}
}

func TestLocalProviderRefuses(t *testing.T) {
	p, err := New(Config{Provider: "local"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "local" {
		t.Errorf("name = %q", p.Name())
	}
	if _, err := p.Wrap(context.Background(), []byte("x")); err == nil {
		t.Error("local Wrap should error")
	}
	if _, err := p.Unwrap(context.Background(), "x"); err == nil {
		t.Error("local Unwrap should error")
	}
	if err := p.Health(context.Background()); err != nil {
		t.Errorf("local Health should succeed, got %v", err)
	}
}

func TestNewUnknownProvider(t *testing.T) {
	if _, err := New(Config{Provider: "hsm9000"}); err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestProviderConfigured(t *testing.T) {
	cases := map[string]bool{"": false, "local": false, "vault-transit": true, "aws-kms": true}
	for p, want := range cases {
		if got := (Config{Provider: p}).ProviderConfigured(); got != want {
			t.Errorf("ProviderConfigured(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestAWSUnwrapRejectsForeignToken guards the self-describing prefix check.
func TestAWSUnwrapRejectsForeignToken(t *testing.T) {
	p, err := New(Config{
		Provider: "aws-kms", AWSRegion: "us-east-1", KeyID: "alias/fleet",
		AWSAccessKey: "AK", AWSSecretKey: "SK",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Unwrap(context.Background(), "vault:v1:abc"); err == nil {
		t.Error("aws-kms Unwrap should reject a Vault token")
	}
}
