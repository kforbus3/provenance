package kms

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"testing"
)

// These integration tests exercise the real provider HTTP paths against live
// backends. They are skipped unless the corresponding backend address is set, so
// the normal `go test` run stays hermetic. Drive them with a Vault dev container
// and/or LocalStack (see the KMS verification steps in the release notes).

func TestVaultTransitRoundTripLive(t *testing.T) {
	addr := os.Getenv("FLEET_KMS_VAULT_ADDR")
	if addr == "" {
		t.Skip("set FLEET_KMS_VAULT_ADDR to run the live Vault Transit test")
	}
	p, err := New(Config{
		Provider:           "vault-transit",
		KeyID:              os.Getenv("FLEET_KMS_KEY_ID"),
		VaultAddr:          addr,
		VaultToken:         os.Getenv("FLEET_KMS_VAULT_TOKEN"),
		VaultTLSSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, p)
}

func TestAWSKMSRoundTripLive(t *testing.T) {
	endpoint := os.Getenv("FLEET_KMS_AWS_ENDPOINT")
	if endpoint == "" {
		t.Skip("set FLEET_KMS_AWS_ENDPOINT (e.g. LocalStack) to run the live AWS KMS test")
	}
	p, err := New(Config{
		Provider:     "aws-kms",
		KeyID:        os.Getenv("FLEET_KMS_KEY_ID"),
		AWSRegion:    os.Getenv("FLEET_KMS_AWS_REGION"),
		AWSAccessKey: os.Getenv("FLEET_KMS_AWS_ACCESS_KEY_ID"),
		AWSSecretKey: os.Getenv("FLEET_KMS_AWS_SECRET_ACCESS_KEY"),
		AWSEndpoint:  endpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, p)
}

func roundTrip(t *testing.T, p Provider) {
	t.Helper()
	ctx := context.Background()
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
	secret := make([]byte, 40)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	token, err := p.Wrap(ctx, secret)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}
	got, err := p.Unwrap(ctx, token)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round-trip mismatch: got %x want %x", got, secret)
	}
	t.Logf("%s round-trip OK (token %d bytes)", p.Name(), len(token))
}
