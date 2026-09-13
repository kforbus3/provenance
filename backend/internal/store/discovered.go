package store

import (
	"context"

	"github.com/google/uuid"
)

// What compose projects exist on the fleet, whether or not Provenance manages
// them.
//
// This is the answer to "what can I keep up to date here", and it needs no setup:
// every compose-managed container records its own project and directory, so the
// monitor sweep already knows. On a real fleet that was sixteen projects across
// seven hosts, in /home, /opt/stacks, /root, /data/compose and /project — no
// convention, no configuration, and nothing for an operator to tell us.
//
// It used to be invisible. The Stacks page listed only what Provenance had
// ADOPTED, and adoption happened as a side effect of a rollout that needed it —
// so a new deployment looked like an empty product with a setup task attached,
// when in fact everything was already discovered and most of it already
// updatable.
type DiscoveredProject struct {
	HostID   uuid.UUID `json:"hostId"`
	Hostname string    `json:"hostname"`
	Project  string    `json:"project"`
	Dir      string    `json:"dir"`
	Services []string  `json:"services"`
	Images   int       `json:"images"`
	// Adopted means Provenance holds this project's compose file, which is needed
	// only to change a version. Rebuilds work without it.
	Adopted bool `json:"adopted"`
	// StackID is set when adopted, so the UI can link to it.
	StackID *uuid.UUID `json:"stackId,omitempty"`
}

// DiscoveredProjects lists every compose project the fleet reports.
// CROSS JOIN LATERAL below, not a comma.
//
// A comma starts a new FROM item, and a LEFT JOIN written after one can only see
// that item -- so hi was out of scope and this did not parse AT ALL: "invalid
// reference to FROM-clause entry for table hi" (SQLSTATE 42P01), on every call,
// from the release that introduced the screen it feeds. The tab showed "no
// compose projects found yet" the whole time, which reads as a fact about the
// fleet rather than a query that could not run.
//
// Nothing caught it because no store query is executed anywhere in the tests:
// the package has no database, and the panel's test mocks this call. A query
// that cannot parse passed the entire gate. See TestStoreQueriesParse.
func (s *Store) DiscoveredProjects(ctx context.Context) ([]DiscoveredProject, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT hi.host_id, h.hostname,
		       c->>'composeProject' AS project,
		       COALESCE(c->>'composeDir','') AS dir,
		       array_agg(DISTINCT COALESCE(NULLIF(c->>'composeService',''), c->>'name')) AS services,
		       count(*) AS images,
		       st.id
		FROM host_inventory hi
		JOIN hosts h ON h.id = hi.host_id
		CROSS JOIN LATERAL jsonb_array_elements(COALESCE(hi.containers, '[]'::jsonb)) AS c
		LEFT JOIN container_stacks st
		       ON st.host_id = hi.host_id AND st.path = COALESCE(c->>'composeDir','')
		WHERE COALESCE(c->>'composeProject','') <> ''
		GROUP BY hi.host_id, h.hostname, 3, 4, st.id
		ORDER BY h.hostname, 3`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DiscoveredProject{}
	for rows.Next() {
		var d DiscoveredProject
		if err := rows.Scan(&d.HostID, &d.Hostname, &d.Project, &d.Dir,
			&d.Services, &d.Images, &d.StackID); err != nil {
			return nil, err
		}
		d.Adopted = d.StackID != nil
		out = append(out, d)
	}
	return out, rows.Err()
}
