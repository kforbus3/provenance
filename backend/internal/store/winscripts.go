package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fleet-terminal/backend/internal/models"
)

const winScriptCols = `id, name, description, content, version, created_by, updated_by, created_at, updated_at`

func scanWinScript(row interface{ Scan(...any) error }) (*models.WinScript, error) {
	var p models.WinScript
	if err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Content, &p.Version,
		&p.CreatedBy, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// ListWinScripts returns scripts ordered by name, omitting body content.
func (s *Store) ListWinScripts(ctx context.Context) ([]*models.WinScript, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, description, '' AS content, version, created_by, updated_by, created_at, updated_at
		 FROM winscripts ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.WinScript
	for rows.Next() {
		p, err := scanWinScript(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetWinScript returns one script including its content.
func (s *Store) GetWinScript(ctx context.Context, id uuid.UUID) (*models.WinScript, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+winScriptCols+` FROM winscripts WHERE id=$1`, id)
	p, err := scanWinScript(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return p, nil
}

// CreateWinScript inserts a new script at version 1 and snapshots it, atomically.
func (s *Store) CreateWinScript(ctx context.Context, name, description, content string, author *uuid.UUID, authorName string) (*models.WinScript, error) {
	content = normalizeContent(content)
	var p *models.WinScript
	err := s.tx(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`INSERT INTO winscripts(name, description, content, version, created_by, updated_by)
			 VALUES($1,$2,$3,1,$4,$4) RETURNING `+winScriptCols,
			name, description, content, author)
		var err error
		p, err = scanWinScript(row)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO winscript_versions(script_id, version, content, author_id, author)
			 VALUES($1,1,$2,$3,$4)`,
			p.ID, content, author, authorName)
		return err
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// UpdateWinScript saves new metadata/content, bumping and snapshotting the version
// when the content changes.
func (s *Store) UpdateWinScript(ctx context.Context, id uuid.UUID, name, description, content string, author *uuid.UUID, authorName string) (*models.WinScript, error) {
	content = normalizeContent(content)
	var p *models.WinScript
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var curContent string
		var curVersion int
		if err := tx.QueryRow(ctx, `SELECT content, version FROM winscripts WHERE id=$1 FOR UPDATE`, id).
			Scan(&curContent, &curVersion); err != nil {
			return mapNotFound(err)
		}
		newVersion := curVersion
		if content != curContent {
			newVersion = curVersion + 1
		}
		row := tx.QueryRow(ctx,
			`UPDATE winscripts SET name=$2, description=$3, content=$4, version=$5,
			        updated_by=$6, updated_at=now()
			 WHERE id=$1 RETURNING `+winScriptCols,
			id, name, description, content, newVersion, author)
		var err error
		p, err = scanWinScript(row)
		if err != nil {
			return err
		}
		if newVersion != curVersion {
			_, err = tx.Exec(ctx,
				`INSERT INTO winscript_versions(script_id, version, content, author_id, author)
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

// DeleteWinScript removes a script (versions + runs cascade).
func (s *Store) DeleteWinScript(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM winscripts WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListWinScriptVersions returns the revision history (newest first), no bodies.
func (s *Store) ListWinScriptVersions(ctx context.Context, scriptID uuid.UUID) ([]*models.WinScriptVersion, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, script_id, version, '' AS content, author, created_at
		 FROM winscript_versions WHERE script_id=$1 ORDER BY version DESC`, scriptID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.WinScriptVersion
	for rows.Next() {
		var v models.WinScriptVersion
		if err := rows.Scan(&v.ID, &v.ScriptID, &v.Version, &v.Content, &v.Author, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &v)
	}
	return out, rows.Err()
}

// GetWinScriptVersion returns a specific revision including its content.
func (s *Store) GetWinScriptVersion(ctx context.Context, scriptID uuid.UUID, version int) (*models.WinScriptVersion, error) {
	var v models.WinScriptVersion
	err := s.pool.QueryRow(ctx,
		`SELECT id, script_id, version, content, author, created_at
		 FROM winscript_versions WHERE script_id=$1 AND version=$2`, scriptID, version).
		Scan(&v.ID, &v.ScriptID, &v.Version, &v.Content, &v.Author, &v.CreatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &v, nil
}

// --- winscript runs ---

const winScriptRunCols = `id, script_id, script_version, requester, target_kind, target_id,
	target_name, host_count, scheduled, status, exit_code, output, error,
	started_at, finished_at, created_at`

func scanWinScriptRun(row interface{ Scan(...any) error }) (*models.WinScriptRun, error) {
	var r models.WinScriptRun
	if err := row.Scan(&r.ID, &r.ScriptID, &r.ScriptVersion, &r.Requester, &r.TargetKind,
		&r.TargetID, &r.TargetName, &r.HostCount, &r.Scheduled, &r.Status, &r.ExitCode,
		&r.Output, &r.Error, &r.StartedAt, &r.FinishedAt, &r.CreatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

// CreateWinScriptRun inserts a pending run and returns it.
func (s *Store) CreateWinScriptRun(ctx context.Context, in models.WinScriptRun, requestedBy *uuid.UUID) (*models.WinScriptRun, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO winscript_runs(script_id, script_version, requested_by, requester,
			target_kind, target_id, target_name, host_count, scheduled, status, instance_id)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10) RETURNING `+winScriptRunCols,
		in.ScriptID, in.ScriptVersion, requestedBy, in.Requester, in.TargetKind,
		in.TargetID, in.TargetName, in.HostCount, in.Scheduled, s.ownerArg())
	return scanWinScriptRun(row)
}

// StartWinScriptRun marks a run as running.
func (s *Store) StartWinScriptRun(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE winscript_runs SET status='running', started_at=now() WHERE id=$1`, id)
	return err
}

// CompleteWinScriptRun records the terminal state, captured output, and exit code.
func (s *Store) CompleteWinScriptRun(ctx context.Context, id uuid.UUID, status, output string, exitCode *int, errMsg string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE winscript_runs SET status=$2, output=$3, exit_code=$4, error=$5, finished_at=now()
		 WHERE id=$1`, id, status, output, exitCode, errMsg)
	return err
}

// GetWinScriptRun returns one run.
func (s *Store) GetWinScriptRun(ctx context.Context, id uuid.UUID) (*models.WinScriptRun, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+winScriptRunCols+` FROM winscript_runs WHERE id=$1`, id)
	r, err := scanWinScriptRun(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return r, nil
}

// ListWinScriptRuns returns recent runs for a script, newest first, without output.
func (s *Store) ListWinScriptRuns(ctx context.Context, scriptID uuid.UUID, limit int) ([]*models.WinScriptRun, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, script_id, script_version, requester, target_kind, target_id,
			target_name, host_count, scheduled, status, exit_code, '' AS output, error,
			started_at, finished_at, created_at
		 FROM winscript_runs WHERE script_id=$1 ORDER BY created_at DESC LIMIT $2`,
		scriptID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.WinScriptRun
	for rows.Next() {
		r, err := scanWinScriptRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// FailStaleWinScriptRuns marks any pending/running runs owned by a dead instance as
// failed on startup, since their in-memory goroutines did not survive the restart.
func (s *Store) FailStaleWinScriptRuns(ctx context.Context, lease time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE winscript_runs SET status='failed', error='interrupted (owning instance stopped)', finished_at=now()
		 WHERE status IN ('pending','running') AND `+deadOwnerPredicate("winscript_runs"), lease.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
