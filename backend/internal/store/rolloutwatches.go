package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// RolloutWatch is one container image on one host that a rollout has just
// updated and is still being watched.
//
// The soak re-check proves a container is running, not unhealthy and not
// restarted. It cannot see a container that is up and failing every request it
// is given, which is what a rollout did to a speech-to-text service on
// 2026-10-04: the healthcheck was a port probe, the error reached the log only
// when real traffic arrived three hours later, and nobody was told. A watch keeps
// tailing the container's logs for error traces after the rollout has moved on.
type RolloutWatch struct {
	ID         uuid.UUID `json:"id"`
	RolloutID  uuid.UUID `json:"rolloutId"`
	HostID     uuid.UUID `json:"hostId"`
	Hostname   string    `json:"hostname,omitempty"`
	Repository string    `json:"repository"`
	ToTag      string    `json:"toTag"`
	StartedAt  time.Time `json:"startedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	// CheckedAt is the log cursor: the next read starts here.
	CheckedAt time.Time `json:"checkedAt"`
	// Regression is the first error trace found, "" while there is none.
	Regression   string     `json:"regression,omitempty"`
	RegressionAt *time.Time `json:"regressionAt,omitempty"`
}

// CreateRolloutWatches opens a watch on each image a host has just verified.
//
// Idempotent per (rollout, host, repository): a host that is re-verified -- a
// retry that got through on its second attempt -- keeps its original cursor
// rather than restarting the window.
func (s *Store) CreateRolloutWatches(ctx context.Context, rollout, host uuid.UUID,
	images []RolloutImage, from time.Time, window time.Duration) error {
	for _, im := range images {
		_, err := s.pool.Exec(ctx, `
			INSERT INTO container_update_rollout_watches
			  (rollout_id, host_id, repository, to_tag, started_at, expires_at, checked_at)
			VALUES ($1, $2, $3, $4, $5, $6, $5)
			ON CONFLICT (rollout_id, host_id, repository) DO NOTHING`,
			rollout, host, im.Repository, im.ToTag, from, from.Add(window))
		if err != nil {
			return err
		}
	}
	return nil
}

// DueRolloutWatches returns the watches whose logs have not been read for at
// least `every`, that have not expired, and that have not already found their
// regression. A watch that has found one is left alone: it is reported once.
func (s *Store) DueRolloutWatches(ctx context.Context, now time.Time, every time.Duration) ([]RolloutWatch, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT w.id, w.rollout_id, w.host_id, COALESCE(h.hostname, ''), w.repository, w.to_tag,
		       w.started_at, w.expires_at, w.checked_at, w.regression, w.regression_at
		FROM container_update_rollout_watches w
		LEFT JOIN hosts h ON h.id = w.host_id
		WHERE w.regression_at IS NULL
		  AND w.expires_at > $1
		  AND w.checked_at <= $2
		ORDER BY w.checked_at
		LIMIT 200`, now, now.Add(-every))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRolloutWatches(rows)
}

// RolloutWatches returns a rollout's watches, for its detail view.
func (s *Store) RolloutWatches(ctx context.Context, rollout uuid.UUID) ([]RolloutWatch, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT w.id, w.rollout_id, w.host_id, COALESCE(h.hostname, ''), w.repository, w.to_tag,
		       w.started_at, w.expires_at, w.checked_at, w.regression, w.regression_at
		FROM container_update_rollout_watches w
		LEFT JOIN hosts h ON h.id = w.host_id
		WHERE w.rollout_id = $1
		ORDER BY h.hostname, w.repository`, rollout)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRolloutWatches(rows)
}

// SetRolloutWatchChecked moves a watch's log cursor to `at` and, when regression
// is non-empty, records it as the one finding this watch will ever make.
func (s *Store) SetRolloutWatchChecked(ctx context.Context, id uuid.UUID, at time.Time, regression string) error {
	if regression == "" {
		_, err := s.pool.Exec(ctx, `
			UPDATE container_update_rollout_watches SET checked_at = $2 WHERE id = $1`, id, at)
		return err
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE container_update_rollout_watches
		SET checked_at = $2, regression = $3, regression_at = $2
		WHERE id = $1 AND regression_at IS NULL`, id, at, regression)
	return err
}

func scanRolloutWatches(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]RolloutWatch, error) {
	out := []RolloutWatch{}
	for rows.Next() {
		var w RolloutWatch
		if err := rows.Scan(&w.ID, &w.RolloutID, &w.HostID, &w.Hostname, &w.Repository, &w.ToTag,
			&w.StartedAt, &w.ExpiresAt, &w.CheckedAt, &w.Regression, &w.RegressionAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}
