package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// RecordingRef pairs a recorded SSH session's metadata with its on-disk recording
// path, for the full-text session-content search to scan.
type RecordingRef struct {
	SessionID uuid.UUID
	Username  string
	Hostname  string
	StartedAt time.Time
	Path      string
}

// RecordingsForSearch returns the most recent recordings (optionally filtered by
// user and host), newest first, bounded by limit. The search scans these files, so
// the caller uses limit to bound how much I/O a single search performs.
func (s *Store) RecordingsForSearch(ctx context.Context, userID, hostID *uuid.UUID, limit int) ([]RecordingRef, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	rows, err := s.pool.Query(ctx, `
		SELECT s.id, COALESCE(s.username::text, ''), COALESCE(s.hostname, ''), s.started_at, r.path
		FROM session_recordings r
		JOIN ssh_sessions s ON s.id = r.ssh_session_id
		WHERE ($1::uuid IS NULL OR s.user_id = $1)
		  AND ($2::uuid IS NULL OR s.host_id = $2)
		ORDER BY s.started_at DESC
		LIMIT $3`, userID, hostID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RecordingRef{}
	for rows.Next() {
		var ref RecordingRef
		if err := rows.Scan(&ref.SessionID, &ref.Username, &ref.Hostname, &ref.StartedAt, &ref.Path); err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}
