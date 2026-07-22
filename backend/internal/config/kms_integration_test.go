package config

import (
	"context"
	"os"
	"testing"

	"github.com/fleet-terminal/backend/internal/kms"
)

// TestResolveSecretsUnwrapsViaKMS proves the full boot path: a KMS-wrapped passphrase
// blob in the environment is unwrapped by ResolveSecrets into the plaintext field the
// CA and vault seal with. Skipped unless a live Vault Transit backend is configured.
func TestResolveSecretsUnwrapsViaKMS(t *testing.T) {
	addr := os.Getenv("FLEET_KMS_VAULT_ADDR")
	if addr == "" {
		t.Skip("set FLEET_KMS_VAULT_ADDR to run the live KMS resolve test")
	}
	const caSecret = "a-real-ca-passphrase-1234567890"
	const vaultSecret = "a-distinct-vault-passphrase-0987"

	kcfg := kms.Config{
		Provider:           "vault-transit",
		KeyID:              os.Getenv("FLEET_KMS_KEY_ID"),
		VaultAddr:          addr,
		VaultToken:         os.Getenv("FLEET_KMS_VAULT_TOKEN"),
		VaultTLSSkipVerify: true,
	}
	prov, err := kms.New(kcfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	caWrapped, err := prov.Wrap(ctx, []byte(caSecret))
	if err != nil {
		t.Fatal(err)
	}
	vaultWrapped, err := prov.Wrap(ctx, []byte(vaultSecret))
	if err != nil {
		t.Fatal(err)
	}

	c := &Config{
		Environment:            "production",
		KMSProvider:            "vault-transit",
		KMSKeyID:               kcfg.KeyID,
		KMSVaultAddr:           addr,
		KMSVaultToken:          kcfg.VaultToken,
		KMSVaultTLSSkipVerify:  true,
		CAKeyPassphraseWrapped: caWrapped,
		VaultPassphraseWrapped: vaultWrapped,
	}
	if err := c.ResolveSecrets(ctx); err != nil {
		t.Fatalf("ResolveSecrets: %v", err)
	}
	if string(c.CAKeyPassphrase) != caSecret {
		t.Errorf("CA passphrase = %q, want %q", c.CAKeyPassphrase, caSecret)
	}
	if c.VaultPassphrase != vaultSecret {
		t.Errorf("vault passphrase = %q, want %q", c.VaultPassphrase, vaultSecret)
	}
	// VaultKey() must now succeed with the unwrapped, distinct passphrase.
	if k, err := c.VaultKey(); err != nil || string(k) != vaultSecret {
		t.Errorf("VaultKey() = %q, %v", k, err)
	}
}
