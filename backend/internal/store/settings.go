package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// SavedFilter is a user's stored dashboard query.
type SavedFilter struct {
	ID        uuid.UUID       `json:"id"`
	UserID    uuid.UUID       `json:"userId"`
	Name      string          `json:"name"`
	Scope     string          `json:"scope"`
	Query     json.RawMessage `json:"query"`
	CreatedAt time.Time       `json:"createdAt"`
}

// GetSetting returns the raw JSON value for a settings key.
func (s *Store) GetSetting(ctx context.Context, key string) (json.RawMessage, error) {
	var v json.RawMessage
	err := s.pool.QueryRow(ctx, `SELECT value FROM settings WHERE key=$1`, key).Scan(&v)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return v, nil
}

// SetSetting upserts a settings key with the given JSON-encodable value.
func (s *Store) SetSetting(ctx context.Context, key string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO settings (key, value, updated_at) VALUES ($1,$2, now())
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, key, b)
	return err
}

// MFAGloballyRequired reports whether the "require_mfa" setting is enabled,
// which forces every user to hold a confirmed second factor. Stored as a JSON
// object {"enabled": bool}; absent/false means MFA stays optional per user.
func (s *Store) MFAGloballyRequired(ctx context.Context) bool {
	raw, err := s.GetSetting(ctx, "require_mfa")
	if err != nil {
		return false
	}
	var v struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	return v.Enabled
}

// RequireWireGuard reports whether strict overlay mode is enabled. When true, a
// host that has a WireGuard address is reachable only over the overlay: the
// terminal and SFTP refuse to fall back to the host's direct address if the
// tunnel is down, so a connection never silently bypasses WireGuard. Stored on
// the "wireguard" settings object as {"requireOverlay": bool}; absent/false
// keeps the normal fallback behavior.
func (s *Store) RequireWireGuard(ctx context.Context) bool {
	raw, err := s.GetSetting(ctx, "wireguard")
	if err != nil {
		return false
	}
	var v struct {
		RequireOverlay bool `json:"requireOverlay"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	return v.RequireOverlay
}

// ScriptTimeout is the maximum time a PowerShell script may run on a single host,
// configurable in Settings (stored on the "scripts" object as
// {"timeoutMinutes": N}). Defaults to 15 minutes; clamped to [1, 240] so a bad
// value can't disable the bound or hold a WinRM session open indefinitely.
func (s *Store) ScriptTimeout(ctx context.Context) time.Duration {
	const def, lo, hi = 15, 1, 240
	raw, err := s.GetSetting(ctx, "scripts")
	if err != nil {
		return def * time.Minute
	}
	var v struct {
		TimeoutMinutes int `json:"timeoutMinutes"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.TimeoutMinutes <= 0 {
		return def * time.Minute
	}
	m := v.TimeoutMinutes
	if m < lo {
		m = lo
	}
	if m > hi {
		m = hi
	}
	return time.Duration(m) * time.Minute
}

// ListSettings returns every setting keyed by name.
func (s *Store) ListSettings(ctx context.Context) (map[string]json.RawMessage, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, value FROM settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]json.RawMessage)
	for rows.Next() {
		var k string
		var v json.RawMessage
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// ListSavedFilters returns a user's saved dashboard filters.
func (s *Store) ListSavedFilters(ctx context.Context, userID uuid.UUID) ([]SavedFilter, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, name, scope, query, created_at FROM saved_filters
		WHERE user_id=$1 ORDER BY scope, name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SavedFilter
	for rows.Next() {
		var f SavedFilter
		if err := rows.Scan(&f.ID, &f.UserID, &f.Name, &f.Scope, &f.Query, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// CreateSavedFilter stores a saved filter for a user.
func (s *Store) CreateSavedFilter(ctx context.Context, userID uuid.UUID, name, scope string, query json.RawMessage) (*SavedFilter, error) {
	if scope == "" {
		scope = "hosts"
	}
	if len(query) == 0 {
		query = json.RawMessage("{}")
	}
	var f SavedFilter
	err := s.pool.QueryRow(ctx, `
		INSERT INTO saved_filters (user_id, name, scope, query) VALUES ($1,$2,$3,$4)
		RETURNING id, user_id, name, scope, query, created_at`,
		userID, name, scope, query).
		Scan(&f.ID, &f.UserID, &f.Name, &f.Scope, &f.Query, &f.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// DeleteSavedFilter removes a saved filter owned by the user.
func (s *Store) DeleteSavedFilter(ctx context.Context, userID, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM saved_filters WHERE id=$1 AND user_id=$2`, id, userID)
	return err
}
