package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

// RecordStatusEvent appends one host online<->offline transition to the
// availability history. Called by the monitor whenever a host crosses the
// reachability boundary; best-effort, so a write failure never blocks the sweep.
func (s *Store) RecordStatusEvent(ctx context.Context, hostID uuid.UUID, from, to, lastErr string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO host_status_events (host_id, from_status, to_status, last_error, at)
		VALUES ($1, $2, $3, $4, $5)`,
		hostID, from, to, lastErr, at)
	return err
}

// StatusEventsForAssistant returns availability transitions in the last `hours`
// (scoped to hosts the user can reach), newest first, optionally for one host.
func (s *Store) StatusEventsForAssistant(ctx context.Context, userID uuid.UUID, isSuperAdmin bool, hostname string, hours, limit int) ([]models.HostStatusEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	if hours <= 0 {
		hours = 168
	}
	args := []any{time.Now().Add(-time.Duration(hours) * time.Hour)}
	where := "WHERE e.at >= $1"
	if hostname != "" {
		args = append(args, hostname)
		where += fmt.Sprintf(" AND h.hostname = $%d", len(args))
	}
	where += accessibleHostsSubquery("e.host_id", userID, isSuperAdmin, &args)
	args = append(args, limit)
	sql := `SELECT e.id, e.host_id, h.hostname, e.from_status, e.to_status, e.last_error, e.at
		FROM host_status_events e JOIN hosts h ON h.id = e.host_id ` + where +
		` ORDER BY e.at DESC LIMIT $` + fmt.Sprint(len(args))
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.HostStatusEvent{}
	for rows.Next() {
		var e models.HostStatusEvent
		if err := rows.Scan(&e.ID, &e.HostID, &e.Hostname, &e.FromStatus, &e.ToStatus, &e.LastError, &e.At); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneStatusEventsBefore deletes availability history older than cutoff. Signature
// matches the other activity-retention prune methods so retentionLoop can call it.
func (s *Store) PruneStatusEventsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM host_status_events WHERE at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
