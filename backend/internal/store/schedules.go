package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

const scheduleCols = `id, name, kind, enabled, target_kind, target_id, target_name,
	recurrence, payload, requester, last_run_at, last_status, next_run_at, created_at, updated_at`

func scanSchedule(row interface{ Scan(...any) error }) (*models.Schedule, error) {
	var s models.Schedule
	var rec, payload []byte
	if err := row.Scan(&s.ID, &s.Name, &s.Kind, &s.Enabled, &s.TargetKind, &s.TargetID,
		&s.TargetName, &rec, &payload, &s.Requester, &s.LastRunAt, &s.LastStatus,
		&s.NextRunAt, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(rec, &s.Recurrence)
	s.Payload = payload
	return &s, nil
}

// scheduleLoc returns the configured display/scheduling timezone (settings key
// "timezone", an IANA name), falling back to the server's local zone.
func (s *Store) scheduleLoc(ctx context.Context) *time.Location {
	if name := s.DisplayTimezone(ctx); name != "" {
		if loc, lerr := time.LoadLocation(name); lerr == nil {
			return loc
		}
	}
	return time.Local
}

// DisplayTimezone returns the configured IANA timezone name (empty if unset).
func (s *Store) DisplayTimezone(ctx context.Context) string {
	raw, err := s.GetSetting(ctx, "timezone")
	if err != nil || len(raw) == 0 {
		return ""
	}
	var cfg struct {
		Timezone string `json:"timezone"`
	}
	if json.Unmarshal(raw, &cfg) == nil {
		return cfg.Timezone
	}
	return ""
}

// ScheduleNextRun computes the next fire time for a recurrence, interpreting
// daily/weekly clock times in the configured scheduling timezone.
func (s *Store) ScheduleNextRun(ctx context.Context, r models.Recurrence) time.Time {
	return NextRun(r, time.Now().In(s.scheduleLoc(ctx)))
}

// RecomputeEnabledNextRuns recomputes next_run_at for every enabled schedule
// (used after the scheduling timezone changes).
func (s *Store) RecomputeEnabledNextRuns(ctx context.Context) error {
	scheds, err := s.ListSchedules(ctx)
	if err != nil {
		return err
	}
	for _, sc := range scheds {
		if !sc.Enabled {
			continue
		}
		next := s.ScheduleNextRun(ctx, sc.Recurrence)
		var nextPtr *time.Time
		if !next.IsZero() {
			nextPtr = &next
		}
		if _, err := s.pool.Exec(ctx,
			`UPDATE schedules SET next_run_at=$2, updated_at=now() WHERE id=$1`, sc.ID, nextPtr); err != nil {
			return err
		}
	}
	return nil
}

// NextRun computes the next fire time for a recurrence after `from` (in from's
// location). Returns zero time if the recurrence is malformed.
func NextRun(r models.Recurrence, from time.Time) time.Time {
	switch r.Type {
	case "interval":
		mins := r.EveryMinutes
		if mins < 1 {
			mins = 60
		}
		return from.Add(time.Duration(mins) * time.Minute)
	case "daily":
		h, m := parseHM(r.TimeOfDay)
		next := time.Date(from.Year(), from.Month(), from.Day(), h, m, 0, 0, from.Location())
		if !next.After(from) {
			next = next.Add(24 * time.Hour)
		}
		return next
	case "weekly":
		h, m := parseHM(r.TimeOfDay)
		next := time.Date(from.Year(), from.Month(), from.Day(), h, m, 0, 0, from.Location())
		// advance to the target weekday
		for int(next.Weekday()) != r.Weekday || !next.After(from) {
			next = next.Add(24 * time.Hour)
		}
		return next
	default:
		return time.Time{}
	}
}

func parseHM(s string) (int, int) {
	var h, m int
	_, _ = fmt.Sscanf(s, "%d:%d", &h, &m)
	if h < 0 || h > 23 {
		h = 0
	}
	if m < 0 || m > 59 {
		m = 0
	}
	return h, m
}

// CreateSchedule inserts a schedule. next_run_at is set if enabled.
func (s *Store) CreateSchedule(ctx context.Context, in *models.Schedule, createdBy *uuid.UUID) (*models.Schedule, error) {
	rec, _ := json.Marshal(in.Recurrence)
	payload := in.Payload
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	var next *time.Time
	if in.Enabled {
		n := s.ScheduleNextRun(ctx, in.Recurrence)
		if !n.IsZero() {
			next = &n
		}
	}
	row := s.pool.QueryRow(ctx,
		`INSERT INTO schedules(name, kind, enabled, target_kind, target_id, target_name,
			recurrence, payload, created_by, requester, next_run_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING `+scheduleCols,
		in.Name, in.Kind, in.Enabled, in.TargetKind, in.TargetID, in.TargetName,
		rec, payload, createdBy, in.Requester, next)
	return scanSchedule(row)
}

// UpdateSchedule replaces editable fields and recomputes next_run_at.
func (s *Store) UpdateSchedule(ctx context.Context, id uuid.UUID, in *models.Schedule) (*models.Schedule, error) {
	rec, _ := json.Marshal(in.Recurrence)
	payload := in.Payload
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	var next *time.Time
	if in.Enabled {
		n := s.ScheduleNextRun(ctx, in.Recurrence)
		if !n.IsZero() {
			next = &n
		}
	}
	row := s.pool.QueryRow(ctx,
		`UPDATE schedules SET name=$2, kind=$3, enabled=$4, target_kind=$5, target_id=$6,
			target_name=$7, recurrence=$8, payload=$9, next_run_at=$10, updated_at=now()
		 WHERE id=$1 RETURNING `+scheduleCols,
		id, in.Name, in.Kind, in.Enabled, in.TargetKind, in.TargetID, in.TargetName,
		rec, payload, next)
	sc, err := scanSchedule(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return sc, nil
}

// SetScheduleEnabled toggles a schedule, recomputing/clearing next_run_at.
func (s *Store) SetScheduleEnabled(ctx context.Context, id uuid.UUID, enabled bool) (*models.Schedule, error) {
	cur, err := s.GetSchedule(ctx, id)
	if err != nil {
		return nil, err
	}
	var next *time.Time
	if enabled {
		n := s.ScheduleNextRun(ctx, cur.Recurrence)
		if !n.IsZero() {
			next = &n
		}
	}
	row := s.pool.QueryRow(ctx,
		`UPDATE schedules SET enabled=$2, next_run_at=$3, updated_at=now()
		 WHERE id=$1 RETURNING `+scheduleCols, id, enabled, next)
	return scanSchedule(row)
}

func (s *Store) GetSchedule(ctx context.Context, id uuid.UUID) (*models.Schedule, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+scheduleCols+` FROM schedules WHERE id=$1`, id)
	sc, err := scanSchedule(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return sc, nil
}

func (s *Store) ListSchedules(ctx context.Context) ([]*models.Schedule, error) {
	// `running` is derived from the launched records: a scan schedule is running
	// while any of its last_run_ids host_scans are pending/running; likewise a
	// playbook schedule against its playbook_runs.
	rows, err := s.pool.Query(ctx, `
		SELECT `+scheduleCols+`,
			CASE
				WHEN kind='scan' THEN EXISTS(
					SELECT 1 FROM host_scans hs
					WHERE hs.id = ANY(schedules.last_run_ids) AND hs.status IN ('pending','running'))
				WHEN kind='playbook' THEN EXISTS(
					SELECT 1 FROM playbook_runs pr
					WHERE pr.id = ANY(schedules.last_run_ids) AND pr.status IN ('pending','running'))
				ELSE false
			END AS running
		FROM schedules ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Schedule
	for rows.Next() {
		var sc models.Schedule
		var rec, payload []byte
		if err := rows.Scan(&sc.ID, &sc.Name, &sc.Kind, &sc.Enabled, &sc.TargetKind, &sc.TargetID,
			&sc.TargetName, &rec, &payload, &sc.Requester, &sc.LastRunAt, &sc.LastStatus,
			&sc.NextRunAt, &sc.CreatedAt, &sc.UpdatedAt, &sc.Running); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(rec, &sc.Recurrence)
		sc.Payload = payload
		out = append(out, &sc)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSchedule(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM schedules WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DueSchedules returns enabled schedules whose next_run_at has passed.
func (s *Store) DueSchedules(ctx context.Context, now time.Time) ([]*models.Schedule, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+scheduleCols+` FROM schedules
		 WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= $1`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Schedule
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// MarkScheduleFired records a fire and sets the next occurrence. runIDs are the
// scan/playbook-run records this fire launched, used to compute in-progress state.
func (s *Store) MarkScheduleFired(ctx context.Context, id uuid.UUID, firedAt time.Time, status string, next time.Time, runIDs []uuid.UUID) error {
	var nextPtr *time.Time
	if !next.IsZero() {
		nextPtr = &next
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE schedules SET last_run_at=$2, last_status=$3, next_run_at=$4, last_run_ids=$5, updated_at=now()
		 WHERE id=$1`, id, firedAt, status, nextPtr, idsOrEmpty(runIDs))
	return err
}

// MarkScheduleRun records a manual ("run now") execution: it stamps the last-run
// time, status, and launched record IDs but leaves next_run_at untouched, so
// triggering a run by hand does not disturb the recurring cadence.
func (s *Store) MarkScheduleRun(ctx context.Context, id uuid.UUID, firedAt time.Time, status string, runIDs []uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE schedules SET last_run_at=$2, last_status=$3, last_run_ids=$4, updated_at=now() WHERE id=$1`,
		id, firedAt, status, idsOrEmpty(runIDs))
	return err
}

// idsOrEmpty normalizes a nil slice to a non-nil empty slice so the uuid[] column
// receives '{}' rather than NULL.
func idsOrEmpty(ids []uuid.UUID) []uuid.UUID {
	if ids == nil {
		return []uuid.UUID{}
	}
	return ids
}
