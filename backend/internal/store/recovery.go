package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ReplaceRecoveryCodes atomically replaces a user's recovery-code set with the
// given hashes (generating new codes invalidates all previous ones).
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, hashes []string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id=$1`, userID); err != nil {
			return err
		}
		for _, h := range hashes {
			if _, err := tx.Exec(ctx,
				`INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, h); err != nil {
				return err
			}
		}
		return nil
	})
}

// ConsumeRecoveryCode marks an unused recovery code used for the user, returning
// true if a matching unused code existed (a single atomic UPDATE, so a code
// cannot be consumed twice by concurrent requests).
func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID uuid.UUID, hash string) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE mfa_recovery_codes SET used_at=now()
		 WHERE user_id=$1 AND code_hash=$2 AND used_at IS NULL`, userID, hash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// RemainingRecoveryCodes returns how many unused recovery codes the user has.
func (s *Store) RemainingRecoveryCodes(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM mfa_recovery_codes WHERE user_id=$1 AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}
