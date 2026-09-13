// Package extsecret resolves "external-backed" vault credentials: secret material held
// in an external secrets manager (HashiCorp Vault KV today) that Provenance fetches on
// demand rather than storing as a locally sealed blob. This lets Provenance broker secrets
// from an organization's existing secrets manager without becoming a second copy of
// record. The provider connection is configured once from the environment; each vault
// secret carries a provider name and an opaque reference.
//
// The default (no provider) path is untouched — non-external secrets continue to use
// the local secretbox-sealed material.
package extsecret

import (
	"context"
	"fmt"
	"strings"
)

// Provider fetches a secret value by an opaque reference from an external manager.
type Provider interface {
	Name() string
	// Fetch returns the plaintext value referenced by ref (implementation-specific
	// format, e.g. "mount/path#field" for Vault KV).
	Fetch(ctx context.Context, ref string) (string, error)
	// Health verifies the backend is reachable/authorized.
	Health(ctx context.Context) error
}

// Writer is a Provider that can also create secrets, not only read them.
//
// Separate from Provider because reading and writing are different trust levels:
// brokering an organization's existing secrets needs a read-only token, and a
// deployment that only does that should not be asked for a writable one. Callers
// type-assert for this and fall back when it is absent.
//
// The one thing Provenance writes is a LUKS recovery passphrase it generated itself
// for an image it is about to build — a secret that has no other copy anywhere,
// which is exactly the case where "we do not become a second copy of record" does
// not apply.
type Writer interface {
	Provider
	// Store writes fields at ref, creating it. Implementations must not silently
	// overwrite an existing secret: a recovery passphrase written over another
	// image's is a machine in the field whose key is gone.
	Store(ctx context.Context, ref string, fields map[string]string) error
}

// StoreIfWritable writes through p when it supports writing, and reports whether
// it did. A provider configured read-only is not an error here — the caller has a
// local vault to fall back to.
func StoreIfWritable(ctx context.Context, p Provider, ref string, fields map[string]string) (bool, error) {
	w, ok := p.(Writer)
	if !ok {
		return false, nil
	}
	return true, w.Store(ctx, ref, fields)
}

// Config selects and configures the external secrets-manager provider. Populated from
// the environment by internal/config.
type Config struct {
	// HashiCorp Vault KV (v2)
	VaultAddr          string
	VaultToken         string
	VaultCACertFile    string
	VaultTLSSkipVerify bool

	// AWS Secrets Manager
	AWSRegion       string
	AWSAccessKey    string
	AWSSecretKey    string
	AWSSessionToken string
	AWSEndpoint     string // optional override (e.g. LocalStack)
}

// Providers is the set of provider names Provenance understands for external secrets. A
// vault secret's external_provider column must be one of these.
const (
	ProviderVaultKV    = "vault-kv"
	ProviderAWSSecrets = "aws-secrets"
)

// Configured reports whether any external secrets-manager connection is set up.
func (c Config) Configured() bool {
	return strings.TrimSpace(c.VaultAddr) != "" ||
		(strings.TrimSpace(c.AWSRegion) != "" && strings.TrimSpace(c.AWSAccessKey) != "")
}

// New constructs the provider for the given name using cfg.
func New(provider string, cfg Config) (Provider, error) {
	switch strings.TrimSpace(provider) {
	case ProviderVaultKV:
		return newVaultKV(cfg)
	case ProviderAWSSecrets:
		return newAWSSecrets(cfg)
	default:
		return nil, fmt.Errorf("extsecret: unknown provider %q (want %s or %s)", provider, ProviderVaultKV, ProviderAWSSecrets)
	}
}

// Supported reports whether a provider name is one Provenance can resolve.
func Supported(provider string) bool {
	return provider == ProviderVaultKV || provider == ProviderAWSSecrets
}
