package store

import (
	"context"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

const scanCols = `id, host_id, requested_by, requester, profile, profile_title, benchmark,
	status, score, pass_count, fail_count, other_count, total_rules, error, skip_rules,
	started_at, finished_at, created_at`

func scanScan(row interface{ Scan(...any) error }) (*models.HostScan, error) {
	var s models.HostScan
	if err := row.Scan(&s.ID, &s.HostID, &s.RequestedBy, &s.Requester, &s.Profile,
		&s.ProfileTitle, &s.Benchmark, &s.Status, &s.Score, &s.PassCount, &s.FailCount,
		&s.OtherCount, &s.TotalRules, &s.Error, &s.SkipRules, &s.StartedAt, &s.FinishedAt, &s.CreatedAt); err != nil {
		return nil, err
	}
	return &s, nil
}

// CreateHostScan inserts a pending scan and returns it.
func (s *Store) CreateHostScan(ctx context.Context, hostID uuid.UUID, requestedBy *uuid.UUID, requester, profile string) (*models.HostScan, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO host_scans(host_id, requested_by, requester, profile, status)
		 VALUES($1,$2,$3,$4,'pending') RETURNING `+scanCols,
		hostID, requestedBy, requester, profile)
	return scanScan(row)
}

// StartHostScan marks a scan running and records the resolved profile/benchmark.
func (s *Store) StartHostScan(ctx context.Context, id uuid.UUID, profile, profileTitle, benchmark string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE host_scans SET status='running', profile=$2, profile_title=$3, benchmark=$4, started_at=now()
		 WHERE id=$1`, id, profile, profileTitle, benchmark)
	return err
}

// ScanSummary holds parsed results persisted on completion.
type ScanSummary struct {
	Score       *float64
	PassCount   int
	FailCount   int
	OtherCount  int
	TotalRules  int
	ReportPath  string
	ResultsPath string
	SkipRules   []string
}

// CompleteHostScan marks a scan completed with its summary + report/results paths.
func (s *Store) CompleteHostScan(ctx context.Context, id uuid.UUID, sum ScanSummary) error {
	skip := sum.SkipRules
	if skip == nil {
		skip = []string{} // column is NOT NULL
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE host_scans SET status='completed', score=$2, pass_count=$3, fail_count=$4,
		 other_count=$5, total_rules=$6, report_path=$7, results_path=$8, skip_rules=$9, finished_at=now() WHERE id=$1`,
		id, sum.Score, sum.PassCount, sum.FailCount, sum.OtherCount, sum.TotalRules, sum.ReportPath, sum.ResultsPath, skip)
	return err
}

// FailStaleScans marks scans still pending/running as failed. A scan's worker
// runs in memory, so any such row at startup was orphaned by a restart.
func (s *Store) FailStaleScans(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE host_scans SET status='failed', error='interrupted (server restarted)', finished_at=now()
		 WHERE status IN ('pending','running')`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ScanResultsPath returns the on-disk results XML path for a scan.
func (s *Store) ScanResultsPath(ctx context.Context, id uuid.UUID) (string, error) {
	var p string
	err := s.pool.QueryRow(ctx, `SELECT results_path FROM host_scans WHERE id=$1`, id).Scan(&p)
	return p, err
}

// FailHostScan marks a scan failed with an error message.
func (s *Store) FailHostScan(ctx context.Context, id uuid.UUID, msg string) error {
	if len(msg) > 1000 {
		msg = msg[:1000]
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE host_scans SET status='failed', error=$2, finished_at=now() WHERE id=$1`, id, msg)
	return err
}

// GetHostScan returns one scan by id.
func (s *Store) GetHostScan(ctx context.Context, id uuid.UUID) (*models.HostScan, error) {
	return scanScan(s.pool.QueryRow(ctx, `SELECT `+scanCols+` FROM host_scans WHERE id=$1`, id))
}

// HostScanReportPath returns the on-disk report path for a scan.
func (s *Store) HostScanReportPath(ctx context.Context, id uuid.UUID) (string, error) {
	var p string
	err := s.pool.QueryRow(ctx, `SELECT report_path FROM host_scans WHERE id=$1`, id).Scan(&p)
	return p, err
}

// ListHostScans returns recent scans for a host, newest first.
func (s *Store) ListHostScans(ctx context.Context, hostID uuid.UUID, limit int) ([]models.HostScan, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+scanCols+` FROM host_scans WHERE host_id=$1 ORDER BY created_at DESC LIMIT $2`, hostID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.HostScan{}
	for rows.Next() {
		sc, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sc)
	}
	return out, rows.Err()
}
