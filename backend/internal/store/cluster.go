package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// RegisterInstance records this backend process in the cluster registry. The id is
// fresh per boot, so a restart appears as a new instance and its prior rows become
// reconcilable.
func (s *Store) RegisterInstance(ctx context.Context, id uuid.UUID, hostname, version string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO cluster_instances (id, hostname, version, started_at, last_heartbeat)
		VALUES ($1, $2, $3, now(), now())
		ON CONFLICT (id) DO UPDATE SET last_heartbeat = now()`,
		id, hostname, version)
	return err
}

// Heartbeat refreshes this instance's liveness timestamp and records whether it
// currently holds leadership (for the cluster roster shown on System Health).
func (s *Store) Heartbeat(ctx context.Context, id uuid.UUID, isLeader bool) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE cluster_instances SET last_heartbeat = now(), is_leader = $2 WHERE id = $1`, id, isLeader)
	return err
}

// ClusterInstance is a member of the backend cluster, for observability.
type ClusterInstance struct {
	ID            uuid.UUID `json:"id"`
	Hostname      string    `json:"hostname"`
	Version       string    `json:"version"`
	IsLeader      bool      `json:"isLeader"`
	StartedAt     time.Time `json:"startedAt"`
	LastHeartbeat time.Time `json:"lastHeartbeat"`
}

// ListClusterInstances returns all registered instances, leader first then newest.
func (s *Store) ListClusterInstances(ctx context.Context) ([]ClusterInstance, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, version, is_leader, started_at, last_heartbeat
		FROM cluster_instances ORDER BY is_leader DESC, started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClusterInstance
	for rows.Next() {
		var c ClusterInstance
		if err := rows.Scan(&c.ID, &c.Hostname, &c.Version, &c.IsLeader, &c.StartedAt, &c.LastHeartbeat); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UnregisterInstance removes this instance on a clean shutdown.
func (s *Store) UnregisterInstance(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM cluster_instances WHERE id = $1`, id)
	return err
}

// LiveInstanceIDs returns the set of instances whose heartbeat is within the lease
// window (i.e. considered alive). Used by ownership-scoped reconciliation.
func (s *Store) LiveInstanceIDs(ctx context.Context, lease time.Duration) (map[uuid.UUID]bool, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id FROM cluster_instances WHERE last_heartbeat > now() - $1::interval`,
		lease.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// deadOwnerPredicate is a SQL fragment (using bind parameter $1 = lease interval as
// text) that matches rows whose owning instance is unknown (legacy/NULL) or no longer
// alive. Reconciliation ANDs this so it only fails work abandoned by a dead instance,
// never a live peer's. The table name qualifies instance_id in the correlated
// subquery.
func deadOwnerPredicate(table string) string {
	return "(" + table + ".instance_id IS NULL OR NOT EXISTS (" +
		"SELECT 1 FROM cluster_instances ci WHERE ci.id = " + table + ".instance_id " +
		"AND ci.last_heartbeat > now() - $1::interval))"
}

// PruneDeadInstances removes instance rows whose heartbeat is older than the grace
// window. Run by the leader after reconciliation has claimed their orphaned work.
func (s *Store) PruneDeadInstances(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM cluster_instances WHERE last_heartbeat < now() - $1::interval`,
		olderThan.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
