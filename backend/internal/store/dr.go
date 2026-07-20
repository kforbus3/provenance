package store

import (
	"context"
	"encoding/json"
)

const drConfigKey = "dr"

// DRConfig is the disaster-recovery configuration for THIS instance. It's advisory
// metadata + orchestration hooks — Fleet does not itself replicate the database or
// move DNS; the webhooks let an operator wire those steps to the failover/failback
// buttons. Stored under the "dr" settings key.
type DRConfig struct {
	// Role is how the operator has labelled this instance: standalone (default,
	// no DR), primary (the active writer), or standby (the warm replica).
	Role string `json:"role"`
	// PeerURL is the other instance's base URL, used only to show peer health.
	PeerURL string `json:"peerUrl"`
	// FailoverWebhook / FailbackWebhook are URLs Fleet POSTs to when an admin
	// triggers the corresponding action — wire them to your promotion / DNS / WG
	// automation. Empty = the action only records intent + (optionally) promotes
	// the local database.
	FailoverWebhook string `json:"failoverWebhook"`
	FailbackWebhook string `json:"failbackWebhook"`
}

// DRConfig returns this instance's DR configuration (zero value = standalone).
func (s *Store) DRConfig(ctx context.Context) DRConfig {
	c := DRConfig{Role: "standalone"}
	raw, err := s.GetSetting(ctx, drConfigKey)
	if err != nil || len(raw) == 0 {
		return c
	}
	_ = json.Unmarshal(raw, &c)
	if c.Role == "" {
		c.Role = "standalone"
	}
	return c
}

// SetDRConfig persists the DR configuration.
func (s *Store) SetDRConfig(ctx context.Context, c DRConfig) error {
	return s.SetSetting(ctx, drConfigKey, c)
}

// DBReplication reports the live PostgreSQL replication posture of THIS instance's
// database: whether it is a standby (in recovery), its replay lag when it is, and
// the connected replicas when it is a primary. Every field degrades gracefully —
// a permission-limited role simply yields zeros rather than an error — so the DR
// page always renders.
type DBReplication struct {
	InRecovery       bool        `json:"inRecovery"`       // true = this DB is a standby/replica
	ReplayLagSeconds *float64    `json:"replayLagSeconds"` // standby: seconds behind the primary
	Replicas         []DRReplica `json:"replicas"`         // primary: connected standbys
}

// DRReplica is one downstream standby as seen by a primary.
type DRReplica struct {
	ClientAddr string `json:"clientAddr"`
	State      string `json:"state"`
	SyncState  string `json:"syncState"`
	LagBytes   *int64 `json:"lagBytes"`
}

func (s *Store) DBReplication(ctx context.Context) (DBReplication, error) {
	var out DBReplication
	if err := s.pool.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&out.InRecovery); err != nil {
		return out, err
	}
	if out.InRecovery {
		// Standby: how far behind are we (by last replayed transaction time)? NULL when
		// fully caught up with no new activity — report 0 in that case.
		var lag *float64
		_ = s.pool.QueryRow(ctx,
			`SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))`).Scan(&lag)
		if lag == nil {
			z := 0.0
			lag = &z
		}
		out.ReplayLagSeconds = lag
		return out, nil
	}
	// Primary: list connected standbys and their byte lag. Needs pg_read_all_stats /
	// superuser to see other sessions' rows; a limited role just returns nothing.
	rows, err := s.pool.Query(ctx, `
		SELECT COALESCE(host(client_addr), ''), state, sync_state,
		       pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn)::bigint
		FROM pg_stat_replication`)
	if err != nil {
		return out, nil // no privilege / no replicas — still a valid (empty) result
	}
	defer rows.Close()
	for rows.Next() {
		var r DRReplica
		if err := rows.Scan(&r.ClientAddr, &r.State, &r.SyncState, &r.LagBytes); err != nil {
			continue
		}
		out.Replicas = append(out.Replicas, r)
	}
	return out, nil
}

// PromoteDB promotes THIS instance's PostgreSQL from standby to primary via
// pg_promote(). It returns the database's error verbatim on failure — most often
// "the server is not in recovery" (already a primary) or a privilege error
// (pg_promote is superuser-only unless EXECUTE is granted) — so the operator sees
// exactly why. Returns whether the promotion request was accepted.
func (s *Store) PromoteDB(ctx context.Context) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT pg_promote()`).Scan(&ok)
	return ok, err
}
