package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fleet-terminal/backend/internal/models"
)

const rdpRecordingCols = `id, host_id, user_id, hostname, fleet_user, rdp_user, format, path,
	size_bytes, duration_ms, status, client_ip, started_at, ended_at`

func scanRDPRecording(row pgx.Row) (*models.RDPRecording, error) {
	var r models.RDPRecording
	err := row.Scan(&r.ID, &r.HostID, &r.UserID, &r.Hostname, &r.FleetUser, &r.RDPUser,
		&r.Format, &r.Path, &r.SizeBytes, &r.DurationMS, &r.Status, &r.ClientIP,
		&r.StartedAt, &r.EndedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &r, nil
}

// RDPRecordingInput carries the fields captured when an RDP session begins. The id
// is supplied by the caller because it is also the guacd recording file name.
type RDPRecordingInput struct {
	ID        uuid.UUID
	HostID    *uuid.UUID
	UserID    *uuid.UUID
	Hostname  string
	FleetUser string
	RDPUser   string
	Path      string
	ClientIP  string
}

// CreateRDPRecording inserts an "active" RDP recording row at session start.
func (s *Store) CreateRDPRecording(ctx context.Context, in RDPRecordingInput) (*models.RDPRecording, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO rdp_recordings (id, host_id, user_id, hostname, fleet_user, rdp_user, path, client_ip, instance_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING `+rdpRecordingCols,
		in.ID, in.HostID, in.UserID, in.Hostname, in.FleetUser, in.RDPUser, in.Path, in.ClientIP, s.ownerArg())
	return scanRDPRecording(row)
}

// FinishRDPRecording marks a recording ended and records its final size/duration.
func (s *Store) FinishRDPRecording(ctx context.Context, id uuid.UUID, sizeBytes, durationMS int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE rdp_recordings
		SET status='ended', ended_at=now(), size_bytes=$2, duration_ms=$3
		WHERE id=$1`, id, sizeBytes, durationMS)
	return err
}

// ListRDPRecordings returns recordings newest-first.
func (s *Store) ListRDPRecordings(ctx context.Context, limit, offset int) ([]*models.RDPRecording, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+rdpRecordingCols+` FROM rdp_recordings
		ORDER BY started_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.RDPRecording
	for rows.Next() {
		rec, err := scanRDPRecording(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// GetRDPRecording returns a single recording by id.
func (s *Store) GetRDPRecording(ctx context.Context, id uuid.UUID) (*models.RDPRecording, error) {
	return scanRDPRecording(s.pool.QueryRow(ctx,
		`SELECT `+rdpRecordingCols+` FROM rdp_recordings WHERE id=$1`, id))
}

// DeleteRDPRecording removes a recording row and returns its on-disk path.
func (s *Store) DeleteRDPRecording(ctx context.Context, id uuid.UUID) (string, error) {
	var path string
	err := s.pool.QueryRow(ctx,
		`DELETE FROM rdp_recordings WHERE id=$1 RETURNING path`, id).Scan(&path)
	if err != nil {
		return "", mapNotFound(err)
	}
	return path, nil
}

// PruneRDPRecordingsBefore deletes recordings started before the cutoff and returns
// their on-disk paths and the total bytes reclaimed.
func (s *Store) PruneRDPRecordingsBefore(ctx context.Context, before time.Time) (paths []string, bytes int64, err error) {
	rows, err := s.pool.Query(ctx,
		`DELETE FROM rdp_recordings WHERE started_at < $1 RETURNING path, size_bytes`, before)
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

// CloseStaleRDPRecordings marks any lingering "active" RDP recordings as ended. Run
// on startup: no RDP session survives a backend restart, so any still marked active
// are stale. (In a future multi-instance HA setup this must be scoped per instance so
// it never finalizes another node's live recording.)
func (s *Store) CloseStaleRDPRecordings(ctx context.Context, lease time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE rdp_recordings SET status='ended', ended_at=COALESCE(ended_at, now())
		 WHERE status='active' AND `+deadOwnerPredicate("rdp_recordings"), lease.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
