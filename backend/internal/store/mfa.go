package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MFAMethod is a registered second factor (secret omitted from API responses).
type MFAMethod struct {
	ID        uuid.UUID `json:"id"`
	Kind      string    `json:"kind"`
	Label     string    `json:"label"`
	Confirmed bool      `json:"confirmed"`
	CreatedAt string    `json:"createdAt"`
}

// CreateTOTPPending stores a new unconfirmed TOTP method, replacing any prior
// unconfirmed one for the user. The secret is stored already-encrypted.
func (s *Store) CreateTOTPPending(ctx context.Context, userID uuid.UUID, label string, encSecret []byte) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`DELETE FROM mfa_methods WHERE user_id=$1 AND kind='totp' AND confirmed=false`, userID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `
			INSERT INTO mfa_methods (user_id, kind, label, secret, confirmed)
			VALUES ($1,'totp',$2,$3,false) RETURNING id`, userID, label, encSecret).Scan(&id)
	})
	return id, err
}

// PendingTOTPSecret returns the encrypted secret of the user's unconfirmed TOTP.
func (s *Store) PendingTOTPSecret(ctx context.Context, userID uuid.UUID) ([]byte, uuid.UUID, error) {
	var sec []byte
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT secret, id FROM mfa_methods
		WHERE user_id=$1 AND kind='totp' AND confirmed=false
		ORDER BY created_at DESC LIMIT 1`, userID).Scan(&sec, &id)
	return sec, id, mapNotFound(err)
}

// ConfirmMFA marks a method confirmed.
func (s *Store) ConfirmMFA(ctx context.Context, userID, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE mfa_methods SET confirmed=true WHERE id=$1 AND user_id=$2`, id, userID)
	return err
}

// ConfirmedTOTPSecrets returns encrypted secrets of all confirmed TOTP methods.
func (s *Store) ConfirmedTOTPSecrets(ctx context.Context, userID uuid.UUID) ([][]byte, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT secret FROM mfa_methods WHERE user_id=$1 AND kind='totp' AND confirmed=true`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// HasConfirmedMFA reports whether the user has any confirmed second factor.
func (s *Store) HasConfirmedMFA(ctx context.Context, userID uuid.UUID) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM mfa_methods WHERE user_id=$1 AND confirmed=true)`, userID).Scan(&ok)
	return ok, err
}

// ListMFA returns a user's methods (without secrets).
func (s *Store) ListMFA(ctx context.Context, userID uuid.UUID) ([]MFAMethod, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, kind, label, confirmed, created_at::text
		FROM mfa_methods WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MFAMethod
	for rows.Next() {
		var m MFAMethod
		if err := rows.Scan(&m.ID, &m.Kind, &m.Label, &m.Confirmed, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteMFA removes one of the user's methods.
func (s *Store) DeleteMFA(ctx context.Context, userID, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM mfa_methods WHERE id=$1 AND user_id=$2`, id, userID)
	return err
}

// ResetUserMFA removes all of a user's factors (admin action).
func (s *Store) ResetUserMFA(ctx context.Context, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM mfa_methods WHERE user_id=$1`, userID)
	return err
}

// TouchMFA records last use.
func (s *Store) TouchMFA(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE mfa_methods SET last_used_at=now() WHERE id=$1`, id)
	return err
}

// TOTPLastStep returns the last accepted TOTP timestep for a user (0 if none).
func (s *Store) TOTPLastStep(ctx context.Context, userID uuid.UUID) (int64, error) {
	var step int64
	err := s.pool.QueryRow(ctx, `SELECT last_totp_step FROM users WHERE id=$1`, userID).Scan(&step)
	return step, err
}

// SetTOTPLastStep advances the last accepted TOTP timestep, never regressing it
// (so a concurrent verify can't lower the replay floor).
func (s *Store) SetTOTPLastStep(ctx context.Context, userID uuid.UUID, step int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET last_totp_step=$2 WHERE id=$1 AND last_totp_step < $2`, userID, step)
	return err
}
