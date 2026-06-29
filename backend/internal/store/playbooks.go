package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fleet-terminal/backend/internal/models"
)

const playbookCols = `id, name, description, content, version, created_by, updated_by, created_at, updated_at`

func scanPlaybook(row interface{ Scan(...any) error }) (*models.Playbook, error) {
	var p models.Playbook
	if err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Content, &p.Version,
		&p.CreatedBy, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// ListPlaybooks returns playbooks ordered by name, omitting body content (the
// list view doesn't need it).
func (s *Store) ListPlaybooks(ctx context.Context) ([]*models.Playbook, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, description, '' AS content, version, created_by, updated_by, created_at, updated_at
		 FROM playbooks ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Playbook
	for rows.Next() {
		p, err := scanPlaybook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPlaybook returns one playbook including its content.
func (s *Store) GetPlaybook(ctx context.Context, id uuid.UUID) (*models.Playbook, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+playbookCols+` FROM playbooks WHERE id=$1`, id)
	p, err := scanPlaybook(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return p, nil
}

// CreatePlaybook inserts a new playbook at version 1 and records the first
// version snapshot, atomically.
func (s *Store) CreatePlaybook(ctx context.Context, name, description, content string, author *uuid.UUID, authorName string) (*models.Playbook, error) {
	var p *models.Playbook
	err := s.tx(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`INSERT INTO playbooks(name, description, content, version, created_by, updated_by)
			 VALUES($1,$2,$3,1,$4,$4) RETURNING `+playbookCols,
			name, description, content, author)
		var err error
		p, err = scanPlaybook(row)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO playbook_versions(playbook_id, version, content, author_id, author)
			 VALUES($1,1,$2,$3,$4)`,
			p.ID, content, author, authorName)
		return err
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// UpdatePlaybook saves new metadata/content. When the content changes, the
// version is bumped and the new content is snapshotted into playbook_versions.
func (s *Store) UpdatePlaybook(ctx context.Context, id uuid.UUID, name, description, content string, author *uuid.UUID, authorName string) (*models.Playbook, error) {
	var p *models.Playbook
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var curContent string
		var curVersion int
		if err := tx.QueryRow(ctx, `SELECT content, version FROM playbooks WHERE id=$1 FOR UPDATE`, id).
			Scan(&curContent, &curVersion); err != nil {
			return mapNotFound(err)
		}
		newVersion := curVersion
		if content != curContent {
			newVersion = curVersion + 1
		}
		row := tx.QueryRow(ctx,
			`UPDATE playbooks SET name=$2, description=$3, content=$4, version=$5,
			        updated_by=$6, updated_at=now()
			 WHERE id=$1 RETURNING `+playbookCols,
			id, name, description, content, newVersion, author)
		var err error
		p, err = scanPlaybook(row)
		if err != nil {
			return err
		}
		if newVersion != curVersion {
			_, err = tx.Exec(ctx,
				`INSERT INTO playbook_versions(playbook_id, version, content, author_id, author)
				 VALUES($1,$2,$3,$4,$5)`,
				id, newVersion, content, author, authorName)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// DeletePlaybook removes a playbook (versions + runs cascade).
func (s *Store) DeletePlaybook(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM playbooks WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListPlaybookVersions returns the revision history (newest first), without
// content bodies.
func (s *Store) ListPlaybookVersions(ctx context.Context, playbookID uuid.UUID) ([]*models.PlaybookVersion, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, playbook_id, version, '' AS content, author, created_at
		 FROM playbook_versions WHERE playbook_id=$1 ORDER BY version DESC`, playbookID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.PlaybookVersion
	for rows.Next() {
		var v models.PlaybookVersion
		if err := rows.Scan(&v.ID, &v.PlaybookID, &v.Version, &v.Content, &v.Author, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &v)
	}
	return out, rows.Err()
}

// GetPlaybookVersion returns a specific revision including its content.
func (s *Store) GetPlaybookVersion(ctx context.Context, playbookID uuid.UUID, version int) (*models.PlaybookVersion, error) {
	var v models.PlaybookVersion
	err := s.pool.QueryRow(ctx,
		`SELECT id, playbook_id, version, content, author, created_at
		 FROM playbook_versions WHERE playbook_id=$1 AND version=$2`, playbookID, version).
		Scan(&v.ID, &v.PlaybookID, &v.Version, &v.Content, &v.Author, &v.CreatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &v, nil
}

// --- playbook runs ---

const playbookRunCols = `id, playbook_id, playbook_version, requester, target_kind, target_id,
	target_name, host_count, check_mode, status, exit_code, output, error,
	started_at, finished_at, created_at`

func scanPlaybookRun(row interface{ Scan(...any) error }) (*models.PlaybookRun, error) {
	var r models.PlaybookRun
	if err := row.Scan(&r.ID, &r.PlaybookID, &r.PlaybookVersion, &r.Requester, &r.TargetKind,
		&r.TargetID, &r.TargetName, &r.HostCount, &r.CheckMode, &r.Status, &r.ExitCode,
		&r.Output, &r.Error, &r.StartedAt, &r.FinishedAt, &r.CreatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

// CreatePlaybookRun inserts a pending run and returns it.
func (s *Store) CreatePlaybookRun(ctx context.Context, in models.PlaybookRun, requestedBy *uuid.UUID) (*models.PlaybookRun, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO playbook_runs(playbook_id, playbook_version, requested_by, requester,
			target_kind, target_id, target_name, host_count, check_mode, status)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending') RETURNING `+playbookRunCols,
		in.PlaybookID, in.PlaybookVersion, requestedBy, in.Requester, in.TargetKind,
		in.TargetID, in.TargetName, in.HostCount, in.CheckMode)
	return scanPlaybookRun(row)
}

// StartPlaybookRun marks a run as running.
func (s *Store) StartPlaybookRun(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE playbook_runs SET status='running', started_at=now() WHERE id=$1`, id)
	return err
}

// CompletePlaybookRun records the terminal state, captured output, and exit code.
func (s *Store) CompletePlaybookRun(ctx context.Context, id uuid.UUID, status, output string, exitCode *int, errMsg string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE playbook_runs SET status=$2, output=$3, exit_code=$4, error=$5, finished_at=now()
		 WHERE id=$1`, id, status, output, exitCode, errMsg)
	return err
}

// GetPlaybookRun returns one run.
func (s *Store) GetPlaybookRun(ctx context.Context, id uuid.UUID) (*models.PlaybookRun, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+playbookRunCols+` FROM playbook_runs WHERE id=$1`, id)
	r, err := scanPlaybookRun(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return r, nil
}

// ListPlaybookRuns returns recent runs for a playbook, newest first, without the
// (potentially large) output body.
func (s *Store) ListPlaybookRuns(ctx context.Context, playbookID uuid.UUID, limit int) ([]*models.PlaybookRun, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, playbook_id, playbook_version, requester, target_kind, target_id,
			target_name, host_count, check_mode, status, exit_code, '' AS output, error,
			started_at, finished_at, created_at
		 FROM playbook_runs WHERE playbook_id=$1 ORDER BY created_at DESC LIMIT $2`,
		playbookID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.PlaybookRun
	for rows.Next() {
		r, err := scanPlaybookRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// FailStalePlaybookRuns marks any pending/running runs as failed on startup,
// since their in-memory goroutines did not survive the restart.
func (s *Store) FailStalePlaybookRuns(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE playbook_runs SET status='failed', error='interrupted (server restarted)', finished_at=now()
		 WHERE status IN ('pending','running')`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
