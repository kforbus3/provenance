package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kforbus3/Moorgate/backend/internal/models"
)

// CreateSession opens a browser session row.
func (s *Store) CreateSession(ctx context.Context, userID uuid.UUID, refreshHash, ip, ua string, mfaPassed bool, expires time.Time) (*models.Session, error) {
	var sess models.Session
	err := s.pool.QueryRow(ctx, `
		INSERT INTO sessions (user_id, refresh_hash, ip, user_agent, mfa_passed, expires_at)
		VALUES ($1,$2,NULLIF($3,'')::inet,$4,$5,$6)
		RETURNING id, user_id, COALESCE(host(ip),''), user_agent, mfa_passed, created_at, last_seen_at, expires_at`,
		userID, refreshHash, ip, ua, mfaPassed, expires).
		Scan(&sess.ID, &sess.UserID, &sess.IP, &sess.UserAgent, &sess.MFAPassed,
			&sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

// GetSession loads a non-revoked session by id.
func (s *Store) GetSession(ctx context.Context, id uuid.UUID) (*models.Session, error) {
	var sess models.Session
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, COALESCE(host(ip),''), user_agent, mfa_passed, created_at,
		       last_seen_at, expires_at, revoked_at
		FROM sessions WHERE id=$1`, id).
		Scan(&sess.ID, &sess.UserID, &sess.IP, &sess.UserAgent, &sess.MFAPassed,
			&sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt, &sess.RevokedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &sess, nil
}

// GetSessionRefreshHash returns the current refresh-token hash for rotation checks.
func (s *Store) GetSessionRefreshHash(ctx context.Context, id uuid.UUID) (string, error) {
	var h string
	err := s.pool.QueryRow(ctx, `SELECT refresh_hash FROM sessions WHERE id=$1`, id).Scan(&h)
	return h, mapNotFound(err)
}

// RotateRefresh updates the stored refresh hash and bumps activity/expiry.
func (s *Store) RotateRefresh(ctx context.Context, id uuid.UUID, newHash string, expires time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE sessions SET refresh_hash=$2, last_seen_at=now(), expires_at=$3 WHERE id=$1`,
		id, newHash, expires)
	return err
}

// TouchSession updates last_seen_at for idle tracking.
func (s *Store) TouchSession(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at=now() WHERE id=$1`, id)
	return err
}

// RevokeSession marks a session revoked.
func (s *Store) RevokeSession(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
	return err
}

// RevokeUserSessions revokes all of a user's sessions (e.g. on disable).
func (s *Store) RevokeUserSessions(ctx context.Context, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID)
	return err
}

// ListUserSessions returns active sessions for a user.
func (s *Store) ListUserSessions(ctx context.Context, userID uuid.UUID) ([]models.Session, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, COALESCE(host(ip),''), user_agent, mfa_passed, created_at,
		       last_seen_at, expires_at, revoked_at
		FROM sessions WHERE user_id=$1 AND revoked_at IS NULL ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Session
	for rows.Next() {
		var sess models.Session
		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.IP, &sess.UserAgent, &sess.MFAPassed,
			&sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt, &sess.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// ListStaleSessions returns active (non-revoked, unexpired) sessions that have
// gone idle past idleTTL or exceeded the absolute lifetime absoluteTTL. A zero
// duration disables that bound. This drives the background reaper so live but
// idle terminal/SFTP connections are torn down even when the owning user makes
// no further HTTP requests (which would otherwise lazily trigger the check).
func (s *Store) ListStaleSessions(ctx context.Context, idleTTL, absoluteTTL time.Duration) ([]models.Session, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, COALESCE(host(ip),''), user_agent, mfa_passed, created_at,
		       last_seen_at, expires_at, revoked_at
		FROM sessions
		WHERE revoked_at IS NULL
		  AND expires_at > now()
		  AND (
		        ($1 > 0 AND last_seen_at < now() - make_interval(secs => $1))
		     OR ($2 > 0 AND created_at   < now() - make_interval(secs => $2))
		      )
		ORDER BY last_seen_at ASC`,
		idleTTL.Seconds(), absoluteTTL.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Session
	for rows.Next() {
		var sess models.Session
		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.IP, &sess.UserAgent, &sess.MFAPassed,
			&sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt, &sess.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// RecordAuthEvent appends a login/security event.
func (s *Store) RecordAuthEvent(ctx context.Context, e models.AuthEvent) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO auth_events (user_id, username, event, ip, user_agent, detail)
		VALUES ($1, NULLIF($2,'')::citext, $3, NULLIF($4,'')::inet, $5, $6)`,
		e.UserID, e.Username, e.Event, e.IP, e.UserAgent, jsonOrEmpty(e.Detail))
	return err
}

// ListAuthEvents returns recent auth events, optionally filtered by user.
func (s *Store) ListAuthEvents(ctx context.Context, userID *uuid.UUID, limit int) ([]models.AuthEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var rows pgx.Rows
	var err error
	if userID != nil {
		rows, err = s.pool.Query(ctx, `
			SELECT id, user_id, COALESCE(username,''), event, COALESCE(host(ip),''),
			       COALESCE(user_agent,''), detail, created_at
			FROM auth_events WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2`, *userID, limit)
	} else {
		rows, err = s.pool.Query(ctx, `
			SELECT id, user_id, COALESCE(username,''), event, COALESCE(host(ip),''),
			       COALESCE(user_agent,''), detail, created_at
			FROM auth_events ORDER BY created_at DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.AuthEvent
	for rows.Next() {
		var e models.AuthEvent
		if err := rows.Scan(&e.ID, &e.UserID, &e.Username, &e.Event, &e.IP, &e.UserAgent, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
