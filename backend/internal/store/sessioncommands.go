package store

import (
	"context"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// UnindexedRecording is a recording the command indexer has not yet processed.
type UnindexedRecording struct {
	RecordingID  uuid.UUID
	SSHSessionID uuid.UUID
	Path         string
}

// UnindexedRecordings returns up to limit asciicast recordings whose commands have not
// been indexed yet (oldest first), for the background command indexer.
func (s *Store) UnindexedRecordings(ctx context.Context, limit int) ([]UnindexedRecording, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, ssh_session_id, path
		FROM session_recordings
		WHERE commands_indexed_at IS NULL AND format = 'asciicast-v2'
		ORDER BY created_at ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UnindexedRecording
	for rows.Next() {
		var r UnindexedRecording
		if err := rows.Scan(&r.RecordingID, &r.SSHSessionID, &r.Path); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SessionCommandInput is one reconstructed command line to index. Offset is seconds
// into the session; the store converts it to an absolute time from the session start.
type SessionCommandInput struct {
	Text   string
	Offset float64
}

// IndexRecordingCommands stores the reconstructed commands for one recording and marks
// it indexed — in a single transaction, so a recording is never left half-indexed. The
// session's user/host/username/hostname/start are looked up to denormalize each row.
// Passing an empty cmds slice still marks the recording indexed (nothing to store).
func (s *Store) IndexRecordingCommands(ctx context.Context, recordingID, sshSessionID uuid.UUID, cmds []SessionCommandInput) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var (
		userID   *uuid.UUID
		hostID   *uuid.UUID
		username string
		hostname string
		started  time.Time
	)
	if err := tx.QueryRow(ctx, `
		SELECT user_id, host_id, COALESCE(username,''), COALESCE(hostname,''), started_at
		FROM ssh_sessions WHERE id = $1`, sshSessionID).
		Scan(&userID, &hostID, &username, &hostname, &started); err != nil {
		return err
	}
	for _, c := range cmds {
		if c.Text == "" {
			continue
		}
		ts := started.Add(time.Duration(c.Offset * float64(time.Second)))
		if _, err := tx.Exec(ctx, `
			INSERT INTO session_commands (ssh_session_id, user_id, host_id, username, hostname, ts, command_text)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			sshSessionID, userID, hostID, username, hostname, ts, c.Text); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE session_recordings SET commands_indexed_at = now() WHERE id = $1`, recordingID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SessionCommandRow is one indexed command matched by a search.
type SessionCommandRow struct {
	Username     string    `json:"username"`
	Hostname     string    `json:"hostname"`
	Command      string    `json:"command"`
	At           time.Time `json:"at"`
	SSHSessionID uuid.UUID `json:"sshSessionId"`
}

// SearchSessionCommands finds indexed commands whose text matches query (full-text
// first, ILIKE substring fallback), newest first. Results are scoped to hosts the
// caller can access (via the full UserCanAccessHost model — group/direct/temporary
// grants minus denials) unless super-admin; an optional hostname narrows to one host.
func (s *Store) SearchSessionCommands(ctx context.Context, userID uuid.UUID, isSuper bool, query, hostname string, limit int) ([]SessionCommandRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	// Over-fetch so per-host access filtering below can still fill `limit` rows.
	fetch := limit * 5
	if fetch > 1000 {
		fetch = 1000
	}
	// Match either as a full-text query (word/phrase) OR as a raw substring, so both
	// "systemctl restart" and "rm -rf" style queries work.
	sql := `
		SELECT sc.host_id, sc.username, sc.hostname, sc.command_text, sc.ts, sc.ssh_session_id
		FROM session_commands sc
		WHERE (to_tsvector('simple', sc.command_text) @@ plainto_tsquery('simple', $1)
		       OR sc.command_text ILIKE '%' || $1 || '%')`
	args := []any{query}
	if hostname != "" {
		args = append(args, hostname)
		sql += ` AND sc.hostname ILIKE '%' || $2 || '%'`
	}
	sql += ` ORDER BY sc.ts DESC LIMIT $` + strconv.Itoa(len(args)+1)
	args = append(args, fetch)

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	access := map[uuid.UUID]bool{} // per-host access cache for this search
	var out []SessionCommandRow
	for rows.Next() {
		var hostID *uuid.UUID
		var r SessionCommandRow
		if err := rows.Scan(&hostID, &r.Username, &r.Hostname, &r.Command, &r.At, &r.SSHSessionID); err != nil {
			return nil, err
		}
		if !isSuper {
			if hostID == nil {
				continue // can't verify access to an unknown host — exclude
			}
			ok, cached := access[*hostID]
			if !cached {
				ok, _ = s.UserCanAccessHost(ctx, userID, *hostID)
				access[*hostID] = ok
			}
			if !ok {
				continue
			}
		}
		out = append(out, r)
		if len(out) >= limit {
			break
		}
	}
	return out, rows.Err()
}
