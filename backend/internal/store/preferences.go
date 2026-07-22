package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GetUserPreference returns the raw JSON value stored under key for a user, or
// (nil, nil) when the user has no value set for that key (not an error — the caller
// applies its own default).
func (s *Store) GetUserPreference(ctx context.Context, userID uuid.UUID, key string) (json.RawMessage, error) {
	var v json.RawMessage
	err := s.pool.QueryRow(ctx,
		`SELECT value FROM user_preferences WHERE user_id=$1 AND key=$2`, userID, key).Scan(&v)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return v, nil
}

// SetUserPreference upserts a user's JSON value for key.
func (s *Store) SetUserPreference(ctx context.Context, userID uuid.UUID, key string, value json.RawMessage) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO user_preferences (user_id, key, value, updated_at)
		 VALUES ($1, $2, $3, now())
		 ON CONFLICT (user_id, key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`,
		userID, key, value)
	return err
}
