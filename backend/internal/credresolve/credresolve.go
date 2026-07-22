// Package credresolve is the single chokepoint that turns a stored vault credential
// into its plaintext. For a normal (locally-sealed) secret it does exactly what every
// call site did before — read the current sealed version and secretbox.Open it. For an
// external-backed secret (external_provider set) it fetches the value on demand from the
// configured external secrets manager instead. Routing every reader through here keeps
// the local path byte-for-byte unchanged while adding the external option uniformly.
package credresolve

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/extsecret"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/secretbox"
	"github.com/fleet-terminal/backend/internal/store"
)

// Open resolves the plaintext for an already-loaded secret. vaultKey is used only for
// the local (non-external) path; extCfg only for the external path.
func Open(ctx context.Context, st *store.Store, secret *models.VaultSecret, vaultKey []byte, extCfg extsecret.Config) ([]byte, error) {
	if secret.ExternalProvider != "" {
		if !extCfg.Configured() {
			return nil, fmt.Errorf("credential is external-backed but no external secrets manager is configured")
		}
		prov, err := extsecret.New(secret.ExternalProvider, extCfg)
		if err != nil {
			return nil, err
		}
		val, err := prov.Fetch(ctx, secret.ExternalRef)
		if err != nil {
			return nil, fmt.Errorf("fetch external secret: %w", err)
		}
		return []byte(val), nil
	}
	sealed, err := st.GetVaultSecretSealed(ctx, secret.ID)
	if err != nil {
		return nil, err
	}
	return secretbox.Open(vaultKey, sealed)
}

// OpenByID loads a secret's metadata and resolves its plaintext in one call.
func OpenByID(ctx context.Context, st *store.Store, id uuid.UUID, vaultKey []byte, extCfg extsecret.Config) (*models.VaultSecret, []byte, error) {
	secret, err := st.GetVaultSecret(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	pt, err := Open(ctx, st, secret, vaultKey, extCfg)
	if err != nil {
		return secret, nil, err
	}
	return secret, pt, nil
}
