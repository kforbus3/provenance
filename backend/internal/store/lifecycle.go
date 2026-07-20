package store

import (
	"context"
	"time"
)

// Lifecycle thresholds (days). Deliberately simple and explainable — an operator
// can predict exactly when an item shows up.
const (
	tokenExpirySoonDays = 30  // token expiring within this window → "expiring"
	tokenStaleDays      = 90  // token unused for this long → "stale"
	tokenNewGraceDays   = 30  // a never-used token younger than this isn't "stale" yet
	credRotateDays      = 90  // vault secret not rotated in this long → "aging"
	passwordAgeDays     = 90  // user password older than this → "aging"
	caKeyAgeDays        = 365 // active CA key older than this → "aging" (informational)
)

// LifecycleItem is one credential/cert-lifecycle observation that may need action.
type LifecycleItem struct {
	Kind    string     `json:"kind"`   // api_token | credential | password | ca_key
	ID      string     `json:"id"`     // source row id (for deep-linking)
	Name    string     `json:"name"`   // token / secret / username / CA label
	Owner   string     `json:"owner"`  // service-account name, secret target, or "" — context
	Status  string     `json:"status"` // expired | expiring | stale | aging
	DueAt   *time.Time `json:"dueAt"`  // expiry instant (tokens); nil for age-based items
	AgeDays int        `json:"ageDays"`
}

// LifecycleReport aggregates expiry/rotation attention items across API tokens,
// vault credentials, user passwords, and the active CA keys. It returns only
// items that need attention (per the thresholds above); a fully-healthy fleet
// returns an empty slice. Everything here is metadata — no secret material.
func (s *Store) LifecycleReport(ctx context.Context, now time.Time) ([]LifecycleItem, error) {
	out := []LifecycleItem{}

	// API tokens (service-account bearer tokens).
	rows, err := s.pool.Query(ctx, `
		SELECT t.id, t.name, u.username, t.expires_at, t.last_used_at, t.created_at
		FROM api_tokens t JOIN users u ON u.id = t.service_account_id
		WHERE t.revoked_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id, name, owner       string
			expiresAt, lastUsedAt *time.Time
			createdAt             time.Time
		)
		if err := rows.Scan(&id, &name, &owner, &expiresAt, &lastUsedAt, &createdAt); err != nil {
			return nil, err
		}
		item := LifecycleItem{Kind: "api_token", ID: id, Name: name, Owner: owner, DueAt: expiresAt}
		switch {
		case expiresAt != nil && !expiresAt.After(now):
			item.Status = "expired"
			item.AgeDays = daysBetween(*expiresAt, now)
		case expiresAt != nil && expiresAt.Before(now.AddDate(0, 0, tokenExpirySoonDays)):
			item.Status = "expiring"
			item.AgeDays = daysBetween(now, *expiresAt)
		case lastUsedAt == nil && createdAt.Before(now.AddDate(0, 0, -tokenNewGraceDays)):
			item.Status = "stale"
			item.AgeDays = daysBetween(createdAt, now)
		case lastUsedAt != nil && lastUsedAt.Before(now.AddDate(0, 0, -tokenStaleDays)):
			item.Status = "stale"
			item.AgeDays = daysBetween(*lastUsedAt, now)
		default:
			continue
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Vault credentials overdue for rotation (updated_at bumps on each new version).
	crows, err := s.pool.Query(ctx, `
		SELECT id, name, target, updated_at FROM vault_secrets
		WHERE updated_at < $1`, now.AddDate(0, 0, -credRotateDays))
	if err != nil {
		return nil, err
	}
	defer crows.Close()
	for crows.Next() {
		var id, name, target string
		var updatedAt time.Time
		if err := crows.Scan(&id, &name, &target, &updatedAt); err != nil {
			return nil, err
		}
		out = append(out, LifecycleItem{
			Kind: "credential", ID: id, Name: name, Owner: target,
			Status: "aging", AgeDays: daysBetween(updatedAt, now),
		})
	}
	if err := crows.Err(); err != nil {
		return nil, err
	}

	// User passwords older than the age threshold (active users only).
	prows, err := s.pool.Query(ctx, `
		SELECT u.id, u.username, c.pw_changed_at
		FROM user_credentials c JOIN users u ON u.id = c.user_id
		WHERE u.is_disabled = false AND c.pw_changed_at < $1`, now.AddDate(0, 0, -passwordAgeDays))
	if err != nil {
		return nil, err
	}
	defer prows.Close()
	for prows.Next() {
		var id, username string
		var changed time.Time
		if err := prows.Scan(&id, &username, &changed); err != nil {
			return nil, err
		}
		out = append(out, LifecycleItem{
			Kind: "password", ID: id, Name: username,
			Status: "aging", AgeDays: daysBetween(changed, now),
		})
	}
	if err := prows.Err(); err != nil {
		return nil, err
	}

	// Active CA keys older than the age threshold (informational rotation hygiene).
	karows, err := s.pool.Query(ctx, `
		SELECT id, kind, created_at FROM ca_keys
		WHERE active = true AND created_at < $1`, now.AddDate(0, 0, -caKeyAgeDays))
	if err != nil {
		return nil, err
	}
	defer karows.Close()
	for karows.Next() {
		var id, kind string
		var createdAt time.Time
		if err := karows.Scan(&id, &kind, &createdAt); err != nil {
			return nil, err
		}
		out = append(out, LifecycleItem{
			Kind: "ca_key", ID: id, Name: kind + " CA",
			Status: "aging", AgeDays: daysBetween(createdAt, now),
		})
	}
	return out, karows.Err()
}

// daysBetween returns the whole-day count from a to b (negative if b precedes a).
func daysBetween(a, b time.Time) int {
	return int(b.Sub(a).Hours() / 24)
}
