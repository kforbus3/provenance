package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

const vaultCheckoutCols = `c.id, c.secret_id, c.user_id, c.reason, c.status, c.requested_at, c.expires_at,
	c.decided_by, c.decided_at, c.checked_in_at`

func scanVaultCheckout(row interface{ Scan(...any) error }) (*models.VaultCheckout, error) {
	var c models.VaultCheckout
	if err := row.Scan(&c.ID, &c.SecretID, &c.UserID, &c.Reason, &c.Status, &c.RequestedAt, &c.ExpiresAt,
		&c.DecidedBy, &c.DecidedAt, &c.CheckedInAt); err != nil {
		return nil, err
	}
	return &c, nil
}

// CreateVaultCheckout stages a check-out. status is "active" (self-service) or
// "pending" (awaiting approval); expiry is now + ttl.
func (s *Store) CreateVaultCheckout(ctx context.Context, secretID, userID uuid.UUID, reason, status string, ttl time.Duration) (*models.VaultCheckout, error) {
	var c models.VaultCheckout
	err := s.pool.QueryRow(ctx, `
		INSERT INTO vault_checkouts (secret_id, user_id, reason, status, expires_at)
		VALUES ($1,$2,$3,$4, now() + $5::interval)
		RETURNING id, secret_id, user_id, reason, status, requested_at, expires_at, decided_by, decided_at, checked_in_at`,
		secretID, userID, reason, status, ttl.String()).Scan(
		&c.ID, &c.SecretID, &c.UserID, &c.Reason, &c.Status, &c.RequestedAt, &c.ExpiresAt,
		&c.DecidedBy, &c.DecidedAt, &c.CheckedInAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// HasActiveCheckout reports whether the user holds an active, unexpired check-out
// of the secret.
func (s *Store) HasActiveCheckout(ctx context.Context, secretID, userID uuid.UUID) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM vault_checkouts
		WHERE secret_id=$1 AND user_id=$2 AND status='active' AND expires_at > now()`, secretID, userID).Scan(&n)
	return n > 0, err
}

// GetVaultCheckout returns a checkout by id.
func (s *Store) GetVaultCheckout(ctx context.Context, id uuid.UUID) (*models.VaultCheckout, error) {
	return scanVaultCheckout(s.pool.QueryRow(ctx, `SELECT `+vaultCheckoutCols+` FROM vault_checkouts c WHERE c.id=$1`, id))
}

// ListMyVaultCheckouts returns a user's recent check-outs (with the secret name).
func (s *Store) ListMyVaultCheckouts(ctx context.Context, userID uuid.UUID, limit int) ([]models.VaultCheckout, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	return s.queryVaultCheckouts(ctx, `
		SELECT `+vaultCheckoutCols+`, s.name, ''
		FROM vault_checkouts c JOIN vault_secrets s ON s.id = c.secret_id
		WHERE c.user_id=$1 ORDER BY c.requested_at DESC LIMIT $2`, userID, limit)
}

// ListPendingVaultCheckouts returns check-outs awaiting approval (for approvers),
// with the secret name and requester username.
func (s *Store) ListPendingVaultCheckouts(ctx context.Context, limit int) ([]models.VaultCheckout, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	return s.queryVaultCheckouts(ctx, `
		SELECT `+vaultCheckoutCols+`, s.name, COALESCE(u.username,'')
		FROM vault_checkouts c
		JOIN vault_secrets s ON s.id = c.secret_id
		LEFT JOIN users u ON u.id = c.user_id
		WHERE c.status='pending' ORDER BY c.requested_at DESC LIMIT $1`, limit)
}

func (s *Store) queryVaultCheckouts(ctx context.Context, sql string, args ...any) ([]models.VaultCheckout, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.VaultCheckout
	for rows.Next() {
		var c models.VaultCheckout
		if err := rows.Scan(&c.ID, &c.SecretID, &c.UserID, &c.Reason, &c.Status, &c.RequestedAt, &c.ExpiresAt,
			&c.DecidedBy, &c.DecidedAt, &c.CheckedInAt, &c.SecretName, &c.Username); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetVaultCheckoutStatus transitions a check-out from `from` to `to` atomically
// (returns false if it was not in the `from` state), stamping the decider on an
// approval/denial and the check-in time on check-in.
func (s *Store) SetVaultCheckoutStatus(ctx context.Context, id uuid.UUID, from, to string, decidedBy *uuid.UUID) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE vault_checkouts
		SET status=$3,
		    decided_by    = CASE WHEN $3 IN ('active','denied') AND $4::uuid IS NOT NULL THEN $4 ELSE decided_by END,
		    decided_at    = CASE WHEN $3 IN ('active','denied') THEN now() ELSE decided_at END,
		    checked_in_at = CASE WHEN $3='checked_in' THEN now() ELSE checked_in_at END
		WHERE id=$1 AND status=$2`, id, from, to, decidedBy)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ExpireVaultCheckouts marks active/pending check-outs past their expiry expired.
func (s *Store) ExpireVaultCheckouts(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE vault_checkouts SET status='expired'
		WHERE status IN ('active','pending') AND expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
