package store

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// HostDependencyEdge is one recorded "this host stands on that one", carrying
// both hostnames so a caller can render it without a second lookup.
type HostDependencyEdge struct {
	HostID      uuid.UUID `json:"hostId"` // the dependent
	Hostname    string    `json:"hostname"`
	DependsOnID uuid.UUID `json:"dependsOnId"` // what it stands on
	DependsOn   string    `json:"dependsOn"`
	Kind        string    `json:"kind"`
	Note        string    `json:"note"`
}

// DependentsOf returns every edge whose TARGET is one of these hosts -- that is,
// everything that stands on them.
//
// This is the direction a blast-radius preview asks in: the question is not what
// the selected hosts need, it is who else falls over when they are touched. The
// reverse index on depends_on_host_id exists for exactly this query.
//
// An empty input returns no rows rather than every row. A bulk action with no
// selection must preview nothing, and a query that quietly widened to the whole
// fleet would render a warning about hosts nobody selected.
func (s *Store) DependentsOf(ctx context.Context, hostIDs []uuid.UUID) ([]HostDependencyEdge, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT d.host_id, dh.hostname, d.depends_on_host_id, th.hostname, d.kind, d.note
		  FROM host_dependencies d
		  JOIN hosts dh ON dh.id = d.host_id
		  JOIN hosts th ON th.id = d.depends_on_host_id
		 WHERE d.depends_on_host_id = ANY($1)
		 ORDER BY th.hostname, dh.hostname`, hostIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostDependencyEdge
	for rows.Next() {
		var e HostDependencyEdge
		if err := rows.Scan(&e.HostID, &e.Hostname, &e.DependsOnID, &e.DependsOn,
			&e.Kind, &e.Note); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// HostDependencyInput is one edge an operator is asserting.
type HostDependencyInput struct {
	HostID      uuid.UUID
	DependsOnID uuid.UUID
	Kind        string
	Note        string
	CreatedBy   *uuid.UUID
}

// ErrDependencyCycle is returned when an edge would close a loop. Its message
// names the path, because "that would create a cycle" sends an operator looking
// for it by hand across a graph they cannot see.
type ErrDependencyCycle struct{ Path []string }

func (e *ErrDependencyCycle) Error() string {
	return "that would make a loop: " + strings.Join(e.Path, " → ")
}

// DependsOn returns what one host stands on.
func (s *Store) DependsOn(ctx context.Context, hostID uuid.UUID) ([]HostDependencyEdge, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT d.host_id, dh.hostname, d.depends_on_host_id, th.hostname, d.kind, d.note
		  FROM host_dependencies d
		  JOIN hosts dh ON dh.id = d.host_id
		  JOIN hosts th ON th.id = d.depends_on_host_id
		 WHERE d.host_id = $1
		 ORDER BY th.hostname, d.kind`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostDependencyEdge
	for rows.Next() {
		var e HostDependencyEdge
		if err := rows.Scan(&e.HostID, &e.Hostname, &e.DependsOnID, &e.DependsOn,
			&e.Kind, &e.Note); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddHostDependency records that one host stands on another.
//
// Refuses a cycle, checked inside the same transaction as the insert so two
// operators adding opposite halves of a loop at once cannot both pass their
// check and both commit. The walk starts from the proposed target and asks
// whether it can already reach the dependent: if it can, adding this edge closes
// the loop.
//
// Depth is bounded. A malformed graph -- one that predates this check, or one
// written directly -- must not turn an insert into a runaway recursive query.
func (s *Store) AddHostDependency(ctx context.Context, in HostDependencyInput) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var path []string
		err := tx.QueryRow(ctx, `
			WITH RECURSIVE walk(id, path, depth) AS (
			    SELECT $1::uuid, ARRAY[(SELECT hostname FROM hosts WHERE id = $1)], 0
			  UNION ALL
			    SELECT d.depends_on_host_id,
			           w.path || (SELECT hostname FROM hosts WHERE id = d.depends_on_host_id),
			           w.depth + 1
			      FROM host_dependencies d
			      JOIN walk w ON w.id = d.host_id
			     WHERE w.depth < 32
			       AND NOT (d.depends_on_host_id = ANY (
			             SELECT h.id FROM hosts h WHERE h.hostname = ANY(w.path)))
			)
			SELECT path FROM walk WHERE id = $2 LIMIT 1`,
			in.DependsOnID, in.HostID).Scan(&path)
		if err == nil {
			// Reached the dependent from the target: this edge would close it.
			self := ""
			if err2 := tx.QueryRow(ctx, `SELECT hostname FROM hosts WHERE id=$1`,
				in.DependsOnID).Scan(&self); err2 == nil {
				path = append(path, self)
			}
			return &ErrDependencyCycle{Path: path}
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO host_dependencies (host_id, depends_on_host_id, kind, note, created_by)
			VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (host_id, depends_on_host_id, kind)
			DO UPDATE SET note = EXCLUDED.note`,
			in.HostID, in.DependsOnID, in.Kind, in.Note, in.CreatedBy)
		return err
	})
}

// DeleteHostDependency removes one edge.
func (s *Store) DeleteHostDependency(ctx context.Context, hostID, dependsOnID uuid.UUID, kind string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM host_dependencies
		  WHERE host_id=$1 AND depends_on_host_id=$2 AND kind=$3`,
		hostID, dependsOnID, kind)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
