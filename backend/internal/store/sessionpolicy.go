package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const sessionPolicyKey = "session_policy"

// SessionPolicy is the global conditional-access policy: which client IP ranges
// may create sessions, and how many concurrent sessions a user may hold. Stored
// under the "session_policy" settings key. The zero value (empty allowlist, 0
// limit) imposes no restriction, so the feature is off until configured.
type SessionPolicy struct {
	IPAllowlist           []string `json:"ipAllowlist"`           // CIDRs / bare IPs; empty = no IP restriction
	MaxConcurrentSessions int      `json:"maxConcurrentSessions"` // 0 = unlimited
}

// SessionPolicy returns the global policy (unrestricted when unset or malformed).
func (s *Store) SessionPolicy(ctx context.Context) SessionPolicy {
	var p SessionPolicy
	raw, err := s.GetSetting(ctx, sessionPolicyKey)
	if err != nil || len(raw) == 0 {
		return p
	}
	_ = json.Unmarshal(raw, &p)
	return p
}

// UserSessionPolicy is a per-user override of the global policy. A nil field
// inherits the global value; a non-nil IPAllowlist that is empty explicitly
// removes the IP restriction for this user.
type UserSessionPolicy struct {
	IPAllowlist           *[]string `json:"ipAllowlist"`
	MaxConcurrentSessions *int      `json:"maxConcurrentSessions"`
	UpdatedAt             time.Time `json:"updatedAt"`
}

// GetUserSessionPolicy returns a user's override, or nil if none is set.
func (s *Store) GetUserSessionPolicy(ctx context.Context, userID uuid.UUID) (*UserSessionPolicy, error) {
	var (
		allowRaw []byte
		maxc     *int
		updated  time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT ip_allowlist, max_concurrent_sessions, updated_at
		FROM user_session_policies WHERE user_id=$1`, userID).Scan(&allowRaw, &maxc, &updated)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	p := &UserSessionPolicy{MaxConcurrentSessions: maxc, UpdatedAt: updated}
	if allowRaw != nil {
		var a []string
		if err := json.Unmarshal(allowRaw, &a); err == nil {
			p.IPAllowlist = &a
		}
	}
	return p, nil
}

// SetUserSessionPolicy upserts a user's override. Pass nil for a field to inherit
// the global value; pass a non-nil empty allowlist to opt this user out of any
// global IP restriction.
func (s *Store) SetUserSessionPolicy(ctx context.Context, userID uuid.UUID, allowlist *[]string, maxc *int) error {
	var allowRaw []byte
	if allowlist != nil {
		allowRaw, _ = json.Marshal(*allowlist)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO user_session_policies (user_id, ip_allowlist, max_concurrent_sessions, updated_at)
		VALUES ($1,$2,$3, now())
		ON CONFLICT (user_id) DO UPDATE SET
			ip_allowlist=EXCLUDED.ip_allowlist,
			max_concurrent_sessions=EXCLUDED.max_concurrent_sessions,
			updated_at=now()`, userID, allowRaw, maxc)
	return err
}

// DeleteUserSessionPolicy removes a user's override so they inherit the global.
func (s *Store) DeleteUserSessionPolicy(ctx context.Context, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM user_session_policies WHERE user_id=$1`, userID)
	return err
}

// CountActiveSessions counts a user's live browser sessions (not revoked, not
// expired) — the denominator for the concurrent-session limit.
func (s *Store) CountActiveSessions(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM sessions
		WHERE user_id=$1 AND revoked_at IS NULL AND expires_at > now()`, userID).Scan(&n)
	return n, err
}
