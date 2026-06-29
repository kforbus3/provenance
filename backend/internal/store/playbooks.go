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
