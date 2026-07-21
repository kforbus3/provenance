package vault

import (
	"context"

	"github.com/fleet-terminal/backend/internal/secretbox"
	"github.com/fleet-terminal/backend/internal/store"
)

// ResealSecrets re-seals every stored vault-secret version to the active KDF profile
// (argon2id→PBKDF2 under FIPS), in place, using the vault passphrase — without ever
// exposing plaintext beyond this process. A version already matching the active
// profile is skipped. Returns the number of versions upgraded. Used by the FIPS
// migration sweep (`fleetctl fips reseal-secrets`).
//
// Vault secrets are versioned; a KDF re-wrap is NOT a value change, so it updates the
// existing row rather than adding a version (preserving history).
func ResealSecrets(ctx context.Context, st *store.Store, key []byte) (int, error) {
	versions, err := st.AllVaultVersionSeals(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, v := range versions {
		out, changed, rerr := secretbox.ResealString(key, v.Sealed)
		if rerr != nil {
			return n, rerr
		}
		if !changed {
			continue
		}
		if uerr := st.UpdateVaultVersionSeal(ctx, v.ID, out); uerr != nil {
			return n, uerr
		}
		n++
	}
	return n, nil
}
