package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// CommandRun is one ad-hoc command execution against one or more hosts.
type CommandRun struct {
	ID         uuid.UUID  `json:"id"`
	Command    string     `json:"command"`
	Requester  string     `json:"requester"`
	TargetKind string     `json:"targetKind"`
	TargetID   *uuid.UUID `json:"targetId,omitempty"`
	TargetName string     `json:"targetName"`
	HostCount  int        `json:"hostCount"`
	Status     string     `json:"status"`
	ExitCode   *int       `json:"exitCode,omitempty"`
	Output     string     `json:"output"`
	Error      string     `json:"error"`
	StartedAt  *time.Time `json:"startedAt,omitempty"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

const commandRunCols = `id, command, requester, target_kind, target_id, target_name,
	host_count, status, exit_code, output, error, started_at, finished_at, created_at`

func scanCommandRun(row interface{ Scan(...any) error }) (*CommandRun, error) {
	var r CommandRun
	err := row.Scan(&r.ID, &r.Command, &r.Requester, &r.TargetKind, &r.TargetID, &r.TargetName,
		&r.HostCount, &r.Status, &r.ExitCode, &r.Output, &r.Error, &r.StartedAt, &r.FinishedAt, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// CreateCommandRun opens a pending run owned by this instance.
func (s *Store) CreateCommandRun(ctx context.Context, in CommandRun, requestedBy *uuid.UUID) (*CommandRun, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO command_runs(command, requested_by, requester, target_kind, target_id,
			target_name, host_count, status, instance_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,'pending',$8) RETURNING `+commandRunCols,
		in.Command, requestedBy, in.Requester, in.TargetKind, in.TargetID, in.TargetName, in.HostCount, s.ownerArg())
	return scanCommandRun(row)
}

func (s *Store) StartCommandRun(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE command_runs SET status='running', started_at=now() WHERE id=$1`, id)
	return err
}

func (s *Store) CompleteCommandRun(ctx context.Context, id uuid.UUID, status, output string, exitCode *int, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE command_runs SET status=$2, output=$3, exit_code=$4, error=$5, finished_at=now()
		WHERE id=$1`, id, status, output, exitCode, errMsg)
	return err
}

func (s *Store) GetCommandRun(ctx context.Context, id uuid.UUID) (*CommandRun, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+commandRunCols+` FROM command_runs WHERE id=$1`, id)
	r, err := scanCommandRun(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return r, nil
}

// ListCommandRuns returns recent runs, newest first, without their output bodies.
func (s *Store) ListCommandRuns(ctx context.Context, limit int) ([]*CommandRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, command, requester, target_kind, target_id, target_name, host_count,
			status, exit_code, '' AS output, error, started_at, finished_at, created_at
		FROM command_runs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*CommandRun{}
	for rows.Next() {
		r, err := scanCommandRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// FailStaleCommandRuns fails pending/running runs abandoned by a dead instance.
func (s *Store) FailStaleCommandRuns(ctx context.Context, lease time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE command_runs SET status='failed', error='interrupted (owning instance stopped)', finished_at=now()
		WHERE status IN ('pending','running') AND `+deadOwnerPredicate("command_runs"), lease.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
