// Package extsecret resolves "external-backed" vault credentials: secret material held
// in an external secrets manager (HashiCorp Vault KV today) that Fleet fetches on
// demand rather than storing as a locally sealed blob. This lets Fleet broker secrets
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

// Config selects and configures the external secrets-manager provider. Populated from
// the environment by internal/config.
type Config struct {
	// HashiCorp Vault KV (v2)
	VaultAddr          string
	VaultToken         string
	VaultCACertFile    string
	VaultTLSSkipVerify bool
}

// Providers is the set of provider names Fleet understands for external secrets. A
// vault secret's external_provider column must be one of these.
const (
	ProviderVaultKV = "vault-kv"
)

// Configured reports whether the external secrets-manager connection is set up (i.e. an
// external-backed secret can actually be resolved).
func (c Config) Configured() bool {
	return strings.TrimSpace(c.VaultAddr) != ""
}

// New constructs the provider for the given name using cfg.
func New(provider string, cfg Config) (Provider, error) {
	switch strings.TrimSpace(provider) {
	case ProviderVaultKV:
		return newVaultKV(cfg)
	default:
		return nil, fmt.Errorf("extsecret: unknown provider %q (want %q)", provider, ProviderVaultKV)
	}
}

// Supported reports whether a provider name is one Fleet can resolve.
func Supported(provider string) bool {
	return provider == ProviderVaultKV
}
