package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// RecordingRetentionDays returns the configured retention in days (0 = keep
// forever) from the settings key "recordings".
func (s *Store) RecordingRetentionDays(ctx context.Context) int {
	raw, err := s.GetSetting(ctx, "recordings")
	if err != nil || len(raw) == 0 {
		return 0
	}
	var v struct {
		RetentionDays int `json:"retentionDays"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return 0
	}
	return v.RetentionDays
}

// DeleteRecordingBySession removes the recording row for an SSH session and
// returns the on-disk path so the caller can delete the file.
func (s *Store) DeleteRecordingBySession(ctx context.Context, sshSessionID uuid.UUID) (string, error) {
	var path string
	err := s.pool.QueryRow(ctx,
		`DELETE FROM session_recordings WHERE ssh_session_id=$1 RETURNING path`, sshSessionID).Scan(&path)
	if err != nil {
		return "", mapNotFound(err)
	}
	return path, nil
}

// PruneRecordingsBefore deletes recording rows created before the cutoff and
// returns their on-disk paths (for file removal) and the total bytes reclaimed.
func (s *Store) PruneRecordingsBefore(ctx context.Context, before time.Time) (paths []string, bytes int64, err error) {
	rows, err := s.pool.Query(ctx,
		`DELETE FROM session_recordings WHERE created_at < $1 RETURNING path, size_bytes`, before)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var p string
		var sz int64
		if err := rows.Scan(&p, &sz); err != nil {
			return nil, 0, err
		}
		paths = append(paths, p)
		bytes += sz
	}
	return paths, bytes, rows.Err()
}

// RecordingSessionIDs returns the set of SSH session ids that have a recording.
func (s *Store) RecordingSessionIDs(ctx context.Context) (map[uuid.UUID]bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT ssh_session_id FROM session_recordings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// CloseStaleSessions marks "active" SSH sessions as closed when their owning
// instance is no longer alive (heartbeat older than lease, or unknown/legacy owner).
// A live PTY exists only in its owning instance's RAM, so once that instance dies the
// row is stale — but sessions owned by a still-live peer are deliberately spared.
func (s *Store) CloseStaleSessions(ctx context.Context, lease time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE ssh_sessions SET status='closed', ended_at=COALESCE(ended_at, now())
		 WHERE status='active' AND `+deadOwnerPredicate("ssh_sessions"), lease.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RecordingsStorageBytes returns the total size of all recordings.
func (s *Store) RecordingsStorageBytes(ctx context.Context) (int64, int64, error) {
	var count, total int64
	err := s.pool.QueryRow(ctx,
		`SELECT count(*), COALESCE(sum(size_bytes),0) FROM session_recordings`).Scan(&count, &total)
	return count, total, err
}
