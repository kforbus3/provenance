package vault

import (
	"bytes"
	"context"
	"fmt"

	"github.com/fleet-terminal/backend/internal/secretbox"
	"github.com/fleet-terminal/backend/internal/store"
)

// RekeyResult reports the outcome of a vault master-key rotation.
type RekeyResult struct {
	Rekeyed    int // versions re-encrypted under the new key this run
	AlreadyNew int // versions already readable with the new key (resume/no-op)
	External   int // external-backed versions with no local sealed material
}

// RekeySecrets rotates the vault master key: it decrypts every locally-sealed vault
// secret version with oldKey and re-encrypts it under newKey, verifying the round-trip
// before writing. This is the remediation for a suspected FLEET_VAULT_PASSPHRASE
// compromise — changing the passphrase alone would render every sealed secret
// undecryptable; this migrates them.
//
// It is RESUMABLE and idempotent per row: a version already readable with newKey is
// skipped, so re-running after an interruption completes the migration. Run it OFFLINE
// (app stopped) so no other writer adds a version under the old key mid-rotation; then
// set FLEET_VAULT_PASSPHRASE to the new value and start the app.
//
// Plaintext never leaves this process and each decrypted buffer is zeroized after use.
func RekeySecrets(ctx context.Context, st *store.Store, oldKey, newKey []byte) (RekeyResult, error) {
	var res RekeyResult
	if bytes.Equal(oldKey, newKey) {
		return res, fmt.Errorf("old and new vault keys are identical — nothing to rotate")
	}
	versions, err := st.AllVaultVersionSeals(ctx)
	if err != nil {
		return res, err
	}
	for _, v := range versions {
		if v.Sealed == "" {
			res.External++
			continue
		}
		// Resume support: if it already opens with the new key, it's migrated.
		if plain, e := secretbox.Open(newKey, v.Sealed); e == nil {
			zero(plain)
			res.AlreadyNew++
			continue
		}
		plain, e := secretbox.Open(oldKey, v.Sealed)
		if e != nil {
			return res, fmt.Errorf("version %s: cannot decrypt with the old key (wrong --old passphrase, or a version under a third key): %w", v.ID, e)
		}
		sealed, e := secretbox.Seal(newKey, plain)
		if e != nil {
			zero(plain)
			return res, fmt.Errorf("version %s: re-seal failed: %w", v.ID, e)
		}
		// Verify the new blob round-trips to the exact plaintext before persisting.
		check, e := secretbox.Open(newKey, sealed)
		ok := e == nil && bytes.Equal(check, plain)
		zero(plain)
		zero(check)
		if !ok {
			return res, fmt.Errorf("version %s: re-encrypted blob failed verification; aborting before write", v.ID)
		}
		if e := st.UpdateVaultVersionSeal(ctx, v.ID, sealed); e != nil {
			return res, fmt.Errorf("version %s: write failed: %w", v.ID, e)
		}
		res.Rekeyed++
	}
	return res, nil
}

// zero overwrites a byte slice (best-effort scrub of decrypted plaintext).
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
