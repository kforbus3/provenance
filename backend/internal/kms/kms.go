// Package kms provides pluggable envelope-encryption backends that protect
// Fleet's master secrets (the CA signing-key passphrase and the credential-vault
// passphrase) with a key held in an external Key Management Service or HSM.
//
// Design — "unseal via KMS". Fleet's at-rest sealing is unchanged: the CA key and
// vault secrets are still AES-256-GCM sealed with a passphrase (see internal/secretbox).
// What a KMS backend changes is where that passphrase lives. Instead of storing the
// plaintext passphrase in the environment, an operator wraps it once with the
// external KMS (`fleetctl kms wrap`) and stores only the opaque wrapped blob
// (FLEET_CA_PASSPHRASE_WRAPPED / FLEET_VAULT_PASSPHRASE_WRAPPED). At boot Fleet makes
// a single Unwrap call to recover the passphrase into memory. An attacker who steals
// the disk and the database still cannot decrypt anything without live access to the
// KMS — which answers the near-universal enterprise review question, "is the master
// key protected by a KMS/HSM?".
//
// The sealed-data format on disk does not change, so enabling (or disabling) a KMS
// backend needs no re-seal of existing secrets — only the passphrase source moves.
// The default provider is "local", which performs no wrapping and preserves the
// prior behavior exactly (no new dependency, no config required).
package kms

import (
	"context"
	"fmt"
	"strings"
)

// Provider wraps and unwraps small secrets (passphrases / data keys) with a key
// held by an external KMS or HSM. Implementations must be safe for concurrent use.
type Provider interface {
	// Name returns the provider identifier (e.g. "vault-transit", "aws-kms").
	Name() string
	// Wrap encrypts plaintext with the external key and returns an opaque,
	// self-describing token suitable for storage in an environment variable.
	Wrap(ctx context.Context, plaintext []byte) (string, error)
	// Unwrap reverses Wrap, returning the original plaintext.
	Unwrap(ctx context.Context, token string) ([]byte, error)
	// Health verifies the backend is reachable and the configured key is usable.
	Health(ctx context.Context) error
}

// Config selects and configures a KMS provider. It is populated from the
// environment by internal/config and passed to New. Kept free of any dependency
// on internal/config to avoid an import cycle.
type Config struct {
	Provider string // "local" (default) | "vault-transit" | "aws-kms"
	KeyID    string // transit key name, or AWS KMS key id / ARN / alias

	// HashiCorp Vault Transit
	VaultAddr          string // e.g. https://vault.internal:8200
	VaultToken         string // Vault token with encrypt/decrypt on the transit key
	VaultCACertFile    string // optional PEM CA bundle for the Vault TLS endpoint
	VaultTLSSkipVerify bool   // dev/test only — never in production

	// AWS KMS
	AWSRegion       string // e.g. us-east-1
	AWSAccessKey    string
	AWSSecretKey    string
	AWSSessionToken string // optional (STS)
	AWSEndpoint     string // optional override (e.g. LocalStack http://localstack:4566)

	// Azure Key Vault
	AzureVaultURL     string // e.g. https://myvault.vault.azure.net
	AzureTenantID     string
	AzureClientID     string
	AzureClientSecret string

	// GCP Cloud KMS. KeyID is the full cryptoKey resource name.
	GCPCredentialsJSON string // service-account key JSON (inline)
	GCPCredentialsFile string // ...or a path to it
}

// ProviderConfigured reports whether an external KMS provider (anything other than
// the no-op "local") is selected.
func (c Config) ProviderConfigured() bool {
	p := strings.TrimSpace(c.Provider)
	return p != "" && p != "local"
}

// New constructs the provider named by cfg.Provider. An empty or "local" provider
// returns a Local backend that refuses wrap/unwrap (there is no external key to use).
func New(cfg Config) (Provider, error) {
	switch strings.TrimSpace(cfg.Provider) {
	case "", "local":
		return Local{}, nil
	case "vault-transit":
		return newVaultTransit(cfg)
	case "aws-kms":
		return newAWSKMS(cfg)
	case "azure-keyvault":
		return newAzureKeyVault(cfg)
	case "gcp-kms":
		return newGCPKMS(cfg)
	default:
		return nil, fmt.Errorf("kms: unknown provider %q (want local|vault-transit|aws-kms|azure-keyvault|gcp-kms)", cfg.Provider)
	}
}

// Local is the default no-op provider. No external key exists, so it cannot wrap or
// unwrap; it exists so callers can construct a Provider unconditionally and so
// `fleetctl kms` fails with a clear message when no backend is configured.
type Local struct{}

func (Local) Name() string { return "local" }

func (Local) Wrap(context.Context, []byte) (string, error) {
	return "", fmt.Errorf("kms: no external provider configured (set FLEET_KMS_PROVIDER)")
}

func (Local) Unwrap(context.Context, string) ([]byte, error) {
	return nil, fmt.Errorf("kms: no external provider configured (set FLEET_KMS_PROVIDER)")
}

func (Local) Health(context.Context) error { return nil }
