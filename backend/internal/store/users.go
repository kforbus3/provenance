package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fleet-terminal/backend/internal/models"
)

// CountUsers returns the total number of accounts (used by the bootstrap gate).
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUserParams carries the inputs needed to create an account.
type CreateUserParams struct {
	Username     string
	Email        string
	DisplayName  string
	PasswordHash string
	IsSuperAdmin bool
	MustChangePw bool
	AuthSource   string // local (default) | oidc | ldap
}

// CreateUser inserts a user and its credential row atomically and returns it.
func (s *Store) CreateUser(ctx context.Context, p CreateUserParams) (*models.User, error) {
	if p.AuthSource == "" {
		p.AuthSource = "local"
	}
	var u models.User
	err := s.tx(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO users (username, email, display_name, is_super_admin, must_change_pw, auth_source)
			VALUES ($1, NULLIF($2,''), $3, $4, $5, $6)
			RETURNING id, username, COALESCE(email,''), display_name, is_super_admin,
			          is_disabled, email_verified, must_change_pw, created_at, updated_at`,
			p.Username, p.Email, p.DisplayName, p.IsSuperAdmin, p.MustChangePw, p.AuthSource)
		if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.IsSuperAdmin,
			&u.IsDisabled, &u.EmailVerified, &u.MustChangePw, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO user_credentials (user_id, password_hash) VALUES ($1, $2)`,
			u.ID, p.PasswordHash)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

const userCols = `id, username, COALESCE(email,''), display_name, is_super_admin,
	is_disabled, email_verified, must_change_pw, require_mfa, auth_source, failed_logins, locked_until,
	last_login_at, created_at, updated_at`

func scanUser(row pgx.Row) (*models.User, error) {
	var u models.User
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.IsSuperAdmin,
		&u.IsDisabled, &u.EmailVerified, &u.MustChangePw, &u.RequireMFA, &u.AuthSource, &u.FailedLogins, &u.LockedUntil,
		&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &u, nil
}

// SetUserRequireMFA toggles whether a user must have a confirmed second factor.
func (s *Store) SetUserRequireMFA(ctx context.Context, id uuid.UUID, require bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET require_mfa=$2, updated_at=now() WHERE id=$1`, id, require)
	return err
}

// GetUserByUsername loads a user by (case-insensitive) username.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE username = $1`, username))
}

// GetUserByEmail loads a user by (case-insensitive) email.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE email = $1`, email))
}

// GetUserByID loads a user by id.
func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE id = $1`, id))
}

// GetPasswordHash returns the stored Argon2id hash for a user.
func (s *Store) GetPasswordHash(ctx context.Context, userID uuid.UUID) (string, error) {
	var h string
	err := s.pool.QueryRow(ctx,
		`SELECT password_hash FROM user_credentials WHERE user_id = $1`, userID).Scan(&h)
	return h, mapNotFound(err)
}

// SetPasswordHash updates a user's password and clears the force-change flag.
func (s *Store) SetPasswordHash(ctx context.Context, userID uuid.UUID, hash string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE user_credentials SET password_hash=$2, pw_changed_at=now()
			WHERE user_id=$1`, userID, hash); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE users SET must_change_pw=false, updated_at=now() WHERE id=$1`, userID)
		return err
	})
}

// ListUsers returns all users with their roles and groups.
func (s *Store) ListUsers(ctx context.Context) ([]models.User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []models.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range users {
		users[i].Roles, _ = s.UserRoleNames(ctx, users[i].ID)
		users[i].Groups, _ = s.UserGroupNames(ctx, users[i].ID)
	}
	return users, nil
}

// UpdateUserParams holds editable user fields.
type UpdateUserParams struct {
	Email       string
	DisplayName string
	IsDisabled  bool
}

// UpdateUser updates editable profile fields.
func (s *Store) UpdateUser(ctx context.Context, id uuid.UUID, p UpdateUserParams) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET email=NULLIF($2,''), display_name=$3, is_disabled=$4, updated_at=now()
		WHERE id=$1`, id, p.Email, p.DisplayName, p.IsDisabled)
	return err
}

// DeleteUser removes a user.
func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	return err
}

// SetDisabled enables/disables an account.
func (s *Store) SetDisabled(ctx context.Context, id uuid.UUID, disabled bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET is_disabled=$2, updated_at=now() WHERE id=$1`, id, disabled)
	return err
}

// SetMustChangePassword toggles the forced-password-change flag.
func (s *Store) SetMustChangePassword(ctx context.Context, id uuid.UUID, must bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET must_change_pw=$2, updated_at=now() WHERE id=$1`, id, must)
	return err
}

// --- Login bookkeeping (lockout) ---

// RecordLoginSuccess resets failure counters and stamps last_login_at.
func (s *Store) RecordLoginSuccess(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET failed_logins=0, locked_until=NULL, last_login_at=now() WHERE id=$1`, id)
	return err
}

// RecordLoginFailure increments the failure counter, locking the account when
// the threshold is reached, and returns the new failure count.
func (s *Store) RecordLoginFailure(ctx context.Context, id uuid.UUID, maxFailed int, lockFor time.Duration) (int, error) {
	var failed int
	err := s.pool.QueryRow(ctx, `
		UPDATE users
		SET failed_logins = failed_logins + 1,
		    locked_until = CASE WHEN failed_logins + 1 >= $2 THEN now() + $3::interval ELSE locked_until END
		WHERE id=$1
		RETURNING failed_logins`,
		id, maxFailed, lockFor.String()).Scan(&failed)
	return failed, err
}

// Unlock clears a lockout.
func (s *Store) Unlock(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=$1`, id)
	return err
}
