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

// DeleteRecordingBySession removes the recording row for an SSH session, and the
// commands indexed from it, and returns the on-disk path so the caller can delete
// the file.
//
// The indexed commands go in the same transaction. They are the recording's
// keystrokes, copied out of it into plaintext rows, and they used to cascade only
// from ssh_sessions -- which retention keeps far longer than the recording, or for
// ever. So deleting a recording deleted the encrypted file and left everything typed
// in it searchable, months later, on the Commands tab, beside a Replay button that
// could only say "No recording is available for this session".
func (s *Store) DeleteRecordingBySession(ctx context.Context, sshSessionID uuid.UUID) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var path string
	if err := tx.QueryRow(ctx,
		`DELETE FROM session_recordings WHERE ssh_session_id=$1 RETURNING path`, sshSessionID).Scan(&path); err != nil {
		return "", mapNotFound(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM session_commands WHERE ssh_session_id=$1`, sshSessionID); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return path, nil
}

// PruneRecordingsBefore deletes recording rows created before the cutoff, and the
// commands indexed from them, and returns their on-disk paths (for file removal) and
// the total bytes reclaimed. See DeleteRecordingBySession for why the commands go too.
//
// Commands are removed only for sessions left with no recording at all, so a session
// that somehow holds a newer recording keeps the commands that recording still backs.
// That check is a second statement, not a CTE beside the DELETE: every part of one
// statement sees the same snapshot, in which the rows being deleted still exist.
func (s *Store) PruneRecordingsBefore(ctx context.Context, before time.Time) (paths []string, bytes int64, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx,
		`DELETE FROM session_recordings WHERE created_at < $1 RETURNING ssh_session_id, path, size_bytes`, before)
	if err != nil {
		return nil, 0, err
	}
	var sessions []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		var p string
		var sz int64
		if err := rows.Scan(&id, &p, &sz); err != nil {
			rows.Close()
			return nil, 0, err
		}
		sessions = append(sessions, id)
		paths = append(paths, p)
		bytes += sz
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(sessions) > 0 {
		if _, err := tx.Exec(ctx, `
			DELETE FROM session_commands sc
			WHERE sc.ssh_session_id = ANY($1)
			  AND NOT EXISTS (SELECT 1 FROM session_recordings r WHERE r.ssh_session_id = sc.ssh_session_id)`,
			sessions); err != nil {
			return nil, 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, err
	}
	return paths, bytes, nil
}

// RecordingSessionIDs reports which of the given sessions have a recording.
//
// Scoped to the ids the caller is about to display. It used to take no argument
// and run `SELECT DISTINCT ssh_session_id FROM session_recordings` -- the whole
// table, with no bound -- collecting every id ever recorded into a map, on
// every single page load of the session list, in order to set a boolean on the
// hundred rows already fetched.
//
// That is invisible on a development database and is the first thing to fall
// over on a real one: the work grows with the total history of the deployment
// rather than with the page being drawn, and recording retention is off by
// default, so nothing ever removes rows from underneath it.
func (s *Store) RecordingSessionIDs(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]bool, error) {
	if len(ids) == 0 {
		return map[uuid.UUID]bool{}, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT ssh_session_id FROM session_recordings WHERE ssh_session_id = ANY($1)`,
		ids)
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
func (s *Store) CloseStaleSessions(ctx context.Context, lease time.Duration, self uuid.UUID) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE ssh_sessions SET status='closed', ended_at=COALESCE(ended_at, now())
		 WHERE status='active' AND `+deadOwnerPredicate("ssh_sessions"), lease.String(), self)
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
