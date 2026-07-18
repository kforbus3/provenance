package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fleet-terminal/backend/internal/models"
)

// serviceAccountSelect aggregates a service account's roles, groups, live token
// count, and most-recent token use in one row.
const serviceAccountSelect = `
	SELECT u.id, u.username, u.display_name, u.is_disabled, u.created_at,
	       COALESCE(array_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL), '{}'),
	       COALESCE(array_agg(DISTINCT g.name) FILTER (WHERE g.name IS NOT NULL), '{}'),
	       COUNT(DISTINCT t.id) FILTER (WHERE t.id IS NOT NULL AND t.revoked_at IS NULL),
	       MAX(t.last_used_at)
	FROM users u
	LEFT JOIN user_roles ur ON ur.user_id = u.id
	LEFT JOIN roles r ON r.id = ur.role_id
	LEFT JOIN user_groups ug ON ug.user_id = u.id
	LEFT JOIN groups g ON g.id = ug.group_id
	LEFT JOIN api_tokens t ON t.service_account_id = u.id
	WHERE u.is_service_account`

func scanServiceAccount(row interface{ Scan(...any) error }) (*models.ServiceAccount, error) {
	var sa models.ServiceAccount
	if err := row.Scan(&sa.ID, &sa.Username, &sa.DisplayName, &sa.IsDisabled, &sa.CreatedAt,
		&sa.Roles, &sa.Groups, &sa.TokenCount, &sa.LastUsedAt); err != nil {
		return nil, mapNotFound(err)
	}
	return &sa, nil
}

// CreateServiceAccount inserts a service-account user (no credential row, so it
// cannot log in interactively). The username must be unique across all users.
func (s *Store) CreateServiceAccount(ctx context.Context, username, displayName string) (*models.ServiceAccount, error) {
	var sa models.ServiceAccount
	err := s.pool.QueryRow(ctx, `
		INSERT INTO users (username, display_name, is_service_account)
		VALUES ($1, $2, true)
		RETURNING id, username, display_name, is_disabled, created_at`,
		username, displayName).Scan(&sa.ID, &sa.Username, &sa.DisplayName, &sa.IsDisabled, &sa.CreatedAt)
	if err != nil {
		return nil, err
	}
	sa.Roles, sa.Groups = []string{}, []string{}
	return &sa, nil
}

// ListServiceAccounts returns every service account with its aggregated detail.
func (s *Store) ListServiceAccounts(ctx context.Context) ([]models.ServiceAccount, error) {
	rows, err := s.pool.Query(ctx, serviceAccountSelect+` GROUP BY u.id ORDER BY u.username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.ServiceAccount{}
	for rows.Next() {
		sa, err := scanServiceAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sa)
	}
	return out, rows.Err()
}

// GetServiceAccount returns one service account, or ErrNotFound.
func (s *Store) GetServiceAccount(ctx context.Context, id uuid.UUID) (*models.ServiceAccount, error) {
	row := s.pool.QueryRow(ctx, serviceAccountSelect+` AND u.id = $1 GROUP BY u.id`, id)
	return scanServiceAccount(row)
}

// SetServiceAccountDisabled toggles a service account's disabled flag (disabled =
// all its tokens are refused, without deleting them).
func (s *Store) SetServiceAccountDisabled(ctx context.Context, id uuid.UUID, disabled bool) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE users SET is_disabled=$2, updated_at=now() WHERE id=$1 AND is_service_account`, id, disabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteServiceAccount removes a service account and, via ON DELETE CASCADE, its
// tokens, role assignments, and group memberships. Refuses non-service-accounts.
func (s *Store) DeleteServiceAccount(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id=$1 AND is_service_account`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetServiceAccountRoles replaces the service account's role set atomically.
func (s *Store) SetServiceAccountRoles(ctx context.Context, id uuid.UUID, roleIDs []uuid.UUID) error {
	return s.replaceMemberships(ctx, id, "user_roles", "role_id", roleIDs)
}

// SetServiceAccountGroups replaces the service account's group set atomically.
func (s *Store) SetServiceAccountGroups(ctx context.Context, id uuid.UUID, groupIDs []uuid.UUID) error {
	return s.replaceMemberships(ctx, id, "user_groups", "group_id", groupIDs)
}

// replaceMemberships clears and re-inserts a service account's rows in a join
// table (user_roles / user_groups) in one transaction. The table/column names are
// fixed internal literals, never user input.
func (s *Store) replaceMemberships(ctx context.Context, id uuid.UUID, table, col string, ids []uuid.UUID) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var isSA bool
		if err := tx.QueryRow(ctx, `SELECT is_service_account FROM users WHERE id=$1`, id).Scan(&isSA); err != nil {
			return mapNotFound(err)
		}
		if !isSA {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE user_id=$1`, id); err != nil {
			return err
		}
		for _, v := range ids {
			if _, err := tx.Exec(ctx,
				`INSERT INTO `+table+` (user_id, `+col+`) VALUES ($1,$2) ON CONFLICT DO NOTHING`, id, v); err != nil {
				return err
			}
		}
		return nil
	})
}

// CreateAPIToken stores a token's hash + metadata for a service account.
func (s *Store) CreateAPIToken(ctx context.Context, saID uuid.UUID, name, hash, prefix string, createdBy uuid.UUID, expiresAt *time.Time) (*models.APIToken, error) {
	var t models.APIToken
	err := s.pool.QueryRow(ctx, `
		INSERT INTO api_tokens (service_account_id, name, token_hash, prefix, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, name, prefix, created_at, expires_at, last_used_at, revoked_at`,
		saID, name, hash, prefix, createdBy, expiresAt).
		Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ListAPITokens returns a service account's tokens, newest first.
func (s *Store) ListAPITokens(ctx context.Context, saID uuid.UUID) ([]models.APIToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, prefix, created_at, expires_at, last_used_at, revoked_at
		FROM api_tokens WHERE service_account_id=$1 ORDER BY created_at DESC`, saID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.APIToken{}
	for rows.Next() {
		var t models.APIToken
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken marks a token revoked (idempotent). It must belong to the given
// service account, so a caller can't revoke another account's token by id.
func (s *Store) RevokeAPIToken(ctx context.Context, saID, tokenID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE api_tokens SET revoked_at=now() WHERE id=$1 AND service_account_id=$2 AND revoked_at IS NULL`,
		tokenID, saID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// APITokenAuth is the minimal data to authenticate an API token.
type APITokenAuth struct {
	TokenID          uuid.UUID
	ServiceAccountID uuid.UUID
	Username         string
	Disabled         bool
	ExpiresAt        *time.Time
	RevokedAt        *time.Time
}

// GetAPITokenByHash looks up a token by its SHA-256 hash, joining its service
// account. Returns ErrNotFound if no matching service-account token exists.
func (s *Store) GetAPITokenByHash(ctx context.Context, hash string) (*APITokenAuth, error) {
	var a APITokenAuth
	err := s.pool.QueryRow(ctx, `
		SELECT t.id, t.service_account_id, u.username, u.is_disabled, t.expires_at, t.revoked_at
		FROM api_tokens t JOIN users u ON u.id = t.service_account_id
		WHERE t.token_hash=$1 AND u.is_service_account`, hash).
		Scan(&a.TokenID, &a.ServiceAccountID, &a.Username, &a.Disabled, &a.ExpiresAt, &a.RevokedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &a, nil
}

// TouchAPIToken records a token's most recent use.
func (s *Store) TouchAPIToken(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE api_tokens SET last_used_at=now() WHERE id=$1`, id)
	return err
}
