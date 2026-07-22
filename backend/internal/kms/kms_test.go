package kms

import (
	"context"
	"testing"
)

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
