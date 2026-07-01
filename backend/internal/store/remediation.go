package store

import (
	"context"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

const remediationCols = `id, scan_id, host_id, requester, rule_ids, status, exit_code,
	output, rescan_id, error, started_at, finished_at, created_at`

func scanRemediation(row interface{ Scan(...any) error }) (*models.HostRemediation, error) {
	var r models.HostRemediation
	if err := row.Scan(&r.ID, &r.ScanID, &r.HostID, &r.Requester, &r.RuleIDs, &r.Status,
		&r.ExitCode, &r.Output, &r.RescanID, &r.Error, &r.StartedAt, &r.FinishedAt, &r.CreatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

// CreateRemediation inserts a pending remediation run.
func (s *Store) CreateRemediation(ctx context.Context, scanID, hostID uuid.UUID, requestedBy *uuid.UUID, requester string, ruleIDs []string) (*models.HostRemediation, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO host_remediations(scan_id, host_id, requested_by, requester, rule_ids, status)
		 VALUES($1,$2,$3,$4,$5,'running') RETURNING `+remediationCols,
		scanID, hostID, requestedBy, requester, ruleIDs)
	r, err := scanRemediation(row)
	if err != nil {
		return nil, err
	}
	_, _ = s.pool.Exec(ctx, `UPDATE host_remediations SET started_at=now() WHERE id=$1`, r.ID)
	return r, err
}

// CompleteRemediation records the outcome of an applied remediation.
func (s *Store) CompleteRemediation(ctx context.Context, id uuid.UUID, exitCode int, output string, rescanID *uuid.UUID) error {
	if len(output) > 100000 {
		output = output[len(output)-100000:]
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE host_remediations SET status='completed', exit_code=$2, output=$3, rescan_id=$4, finished_at=now() WHERE id=$1`,
		id, exitCode, output, rescanID)
	return err
}

// FailRemediation marks a remediation failed.
func (s *Store) FailRemediation(ctx context.Context, id uuid.UUID, msg string) error {
	if len(msg) > 2000 {
		msg = msg[:2000]
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE host_remediations SET status='failed', error=$2, finished_at=now() WHERE id=$1`, id, msg)
	return err
}

// FailStaleRemediations marks remediations still pending/running as failed
// (their in-memory worker did not survive a restart).
func (s *Store) FailStaleRemediations(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE host_remediations SET status='failed', error='interrupted (server restarted)', finished_at=now()
		 WHERE status IN ('pending','running')`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// GetRemediation returns one remediation run.
func (s *Store) GetRemediation(ctx context.Context, id uuid.UUID) (*models.HostRemediation, error) {
	return scanRemediation(s.pool.QueryRow(ctx, `SELECT `+remediationCols+` FROM host_remediations WHERE id=$1`, id))
}

// ListRemediationJobs returns recent remediation runs as lightweight job-log
// views (joined to the host for its name, omitting the output blob). Most-recent
// first so the job log surfaces in-progress runs at the top.
func (s *Store) ListRemediationJobs(ctx context.Context, limit int) ([]models.RemediationJob, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT r.id, r.host_id, COALESCE(h.hostname, ''), r.requester,
		       COALESCE(array_length(r.rule_ids, 1), 0), r.status, r.exit_code,
		       r.error, r.started_at, r.finished_at, r.created_at
		FROM host_remediations r
		LEFT JOIN hosts h ON h.id = r.host_id
		ORDER BY r.created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.RemediationJob{}
	for rows.Next() {
		var j models.RemediationJob
		if err := rows.Scan(&j.ID, &j.HostID, &j.Hostname, &j.Requester, &j.RuleCount,
			&j.Status, &j.ExitCode, &j.Error, &j.StartedAt, &j.FinishedAt, &j.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
