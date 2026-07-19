// Package cluster provides the High-Availability primitives shared by all backend
// instances: a per-process identity, a heartbeat lease recorded in Postgres, and
// leader election via a Postgres session-scoped advisory lock.
//
// Leadership is whoever holds the advisory lock. Because the lock is session-scoped,
// it auto-releases the instant the holder's connection drops (crash, network
// partition, or clean shutdown), so a new leader is elected without any timeout
// bookkeeping and without split brain. Singleton background work (P1) runs only on
// the leader; ownership-scoped reconciliation (P2) uses the heartbeat lease to tell
// which instances are still alive.
//
// A single-instance deployment is simply always the leader — HA is safe by default,
// with no feature flag.
package cluster

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fleet-terminal/backend/internal/store"
)

// leaderLockKey is the fixed advisory-lock key contended for leadership. Arbitrary
// but must be identical across all instances (and not collide with other advisory
// locks — Fleet uses none elsewhere).
const leaderLockKey int64 = 0x466C74484100 // "FltHA"

const (
	// HeartbeatInterval is how often an instance refreshes its lease and re-checks
	// leadership.
	HeartbeatInterval = 10 * time.Second
	// Lease is how long an instance may be silent before it is considered dead.
	// Must comfortably exceed HeartbeatInterval to tolerate a slow beat.
	Lease = 30 * time.Second
	// pruneGrace is how long a dead instance's row is kept before the leader prunes
	// it (well past Lease, so reconciliation has claimed its work first).
	pruneGrace = 5 * time.Minute
)

// Coordinator runs one backend instance's cluster membership: identity, heartbeat,
// and leader election.
type Coordinator struct {
	id       uuid.UUID
	hostname string
	version  string
	store    *store.Store
	pool     *pgxpool.Pool
	log      *slog.Logger

	mu       sync.RWMutex
	leader   bool
	lockConn *pgxpool.Conn // held only while this instance is the leader
}

// New builds a coordinator with a fresh per-boot identity.
func New(st *store.Store, hostname, version string, log *slog.Logger) *Coordinator {
	return &Coordinator{
		id: uuid.New(), hostname: hostname, version: version,
		store: st, pool: st.Pool(), log: log,
	}
}

// ID is this instance's per-boot identity, used to tag owned work.
func (c *Coordinator) ID() uuid.UUID { return c.id }

// IsLeader reports whether this instance currently holds leadership.
func (c *Coordinator) IsLeader() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.leader
}

// Run registers the instance and drives the heartbeat + election loop until ctx is
// cancelled, then releases leadership and unregisters. Blocking; run in a goroutine.
func (c *Coordinator) Run(ctx context.Context) {
	if err := c.store.RegisterInstance(ctx, c.id, c.hostname, c.version); err != nil {
		c.log.Warn("cluster: register instance failed", "err", err)
	}
	c.tick(ctx) // attempt leadership immediately so a solo instance leads at once

	t := time.NewTicker(HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.shutdown()
			return
		case <-t.C:
			c.tick(ctx)
		}
	}
}

// tick (re)evaluates leadership, then refreshes the heartbeat (recording the current
// leadership state for the roster).
func (c *Coordinator) tick(ctx context.Context) {
	c.evaluateLeadership(ctx)
	leader := c.IsLeader()
	if err := c.store.Heartbeat(ctx, c.id, leader); err != nil {
		c.log.Warn("cluster: heartbeat failed", "err", err)
	}
	if leader {
		if _, err := c.store.PruneDeadInstances(ctx, pruneGrace); err != nil {
			c.log.Debug("cluster: prune dead instances failed", "err", err)
		}
	}
}

// evaluateLeadership acquires the advisory lock if we don't hold it, or verifies our
// held connection is still alive if we do.
func (c *Coordinator) evaluateLeadership(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.lockConn != nil {
		// Verify the connection (and thus the lock) is still live.
		if err := c.lockConn.Ping(ctx); err != nil {
			c.log.Warn("cluster: lost leader connection, stepping down", "err", err)
			c.lockConn.Release()
			c.lockConn = nil
			c.leader = false
		} else {
			return // still leader
		}
	}

	// Not currently leader: try to acquire on a fresh dedicated connection.
	conn, err := c.pool.Acquire(ctx)
	if err != nil {
		c.log.Debug("cluster: acquire conn for election failed", "err", err)
		return
	}
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, leaderLockKey).Scan(&got); err != nil {
		c.log.Debug("cluster: advisory lock query failed", "err", err)
		conn.Release()
		return
	}
	if !got {
		conn.Release() // another instance is the leader
		return
	}
	// We are the new leader; hold the connection to hold the lock.
	c.lockConn = conn
	if !c.leader {
		c.leader = true
		c.log.Info("cluster: acquired leadership", "instance", c.id)
	}
}

// shutdown releases leadership and removes this instance from the registry so
// failover happens immediately on a clean stop.
func (c *Coordinator) shutdown() {
	c.mu.Lock()
	if c.lockConn != nil {
		// Best-effort explicit unlock, then release the connection (which also frees
		// the session-scoped lock).
		_, _ = c.lockConn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, leaderLockKey)
		c.lockConn.Release()
		c.lockConn = nil
	}
	c.leader = false
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.store.UnregisterInstance(ctx, c.id); err != nil {
		c.log.Debug("cluster: unregister failed", "err", err)
	}
}
