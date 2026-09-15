package store

import (
	"context"

	"github.com/google/uuid"
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
