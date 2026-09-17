package store

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kforbus3/provenance/backend/internal/models"
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
// TouchSession records that a session is still in use.
//
// Only once a minute per session. It ran on EVERY authenticated request, which
// makes an idle dashboard a write workload: five polling queries every thirty
// seconds per open tab, each one a row update, so thirty operators with the
// dashboard open wrote to this table five times a second purely for bookkeeping
// -- and every one of those updates is a dead tuple for autovacuum to collect on
// a table that is read on every request.
//
// A minute of resolution is more than the value is ever read at: last_seen_at
// drives the session list and stale-session reaping, neither of which can tell
// the difference.
func (s *Store) TouchSession(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE sessions SET last_seen_at=now()
		 WHERE id=$1 AND (last_seen_at IS NULL OR last_seen_at < now() - interval '1 minute')`, id)
	return err
}

// RevokeSession marks a session revoked.
func (s *Store) RevokeSession(ctx context.Context, id uuid.UUID) error {
	// Matching nothing is a failure, not a no-op: a session reported revoked but still live is an open door.
	tag, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
	return changed(tag, err)
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

// ActiveSession is a live session with the username attached, for the admin
// "who is signed in right now" view. models.Session carries only a user id, and
// a list of UUIDs is not something an operator can act on.
type ActiveSession struct {
	models.Session
	Username    string `json:"username"`
	DisplayName string `json:"displayName,omitempty"`
}

// ListActiveSessions returns every session that is currently usable, newest
// activity first, across all users.
//
// "Currently usable" is not the same test ListUserSessions applies. That one
// filters on revoked_at alone, which is right for its callers -- they are about
// to end every one of them, and ending an already-expired session is harmless.
// It is wrong for a display: an expired row is not somebody signed in, and
// showing it invites an operator to terminate a session that ended by itself
// days ago, then wonder why nothing changed.
//
// The bound matters because this is the query behind a screen an operator reads
// to decide whether to cut somebody off.
func (s *Store) ListActiveSessions(ctx context.Context, q string, limit int) ([]ActiveSession, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	// Filtered in SQL rather than in the browser. The limit is the reason: the
	// query returns at most `limit` rows, so filtering after the fact searches
	// only the page that happened to come back — on a fleet with more sessions
	// than that, looking for one person's would silently miss them. The whole
	// point of the search is the case where the list is too long to read.
	//
	// Username, display name and address, because "find this user's sessions" and
	// "find whoever is on this address" are the same job from an operator's side.
	rows, err := s.pool.Query(ctx, `
		SELECT s.id, s.user_id, COALESCE(host(s.ip),''), s.user_agent, s.mfa_passed,
		       s.created_at, s.last_seen_at, s.expires_at, s.revoked_at,
		       u.username, u.display_name
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.revoked_at IS NULL AND s.expires_at > now()
		  AND ($2 = '' OR u.username ILIKE '%' || $2 || '%'
		                OR u.display_name ILIKE '%' || $2 || '%'
		                OR COALESCE(host(s.ip),'') ILIKE '%' || $2 || '%')
		ORDER BY s.last_seen_at DESC NULLS LAST
		LIMIT $1`, limit, strings.TrimSpace(q))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ActiveSession{}
	for rows.Next() {
		var a ActiveSession
		if err := rows.Scan(&a.ID, &a.UserID, &a.IP, &a.UserAgent, &a.MFAPassed,
			&a.CreatedAt, &a.LastSeenAt, &a.ExpiresAt, &a.RevokedAt,
			&a.Username, &a.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
