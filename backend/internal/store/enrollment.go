package store

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kforbus3/Moorgate/backend/internal/models"
)

// CreateEnrollmentJob opens an enrollment job for a host.
func (s *Store) CreateEnrollmentJob(ctx context.Context, hostID uuid.UUID, target, osHint string, createdBy *uuid.UUID) (*models.EnrollmentJob, error) {
	var j models.EnrollmentJob
	var steps []byte
	err := s.pool.QueryRow(ctx, `
		INSERT INTO enrollment_jobs (host_id, target, os_hint, status, created_by, started_at, instance_id)
		VALUES ($1,$2,$3,'running',$4, now(),$5)
		RETURNING id, host_id, target, os_hint, status, steps, error, created_by, created_at, started_at, finished_at`,
		hostID, target, osHint, createdBy, s.ownerArg()).
		Scan(&j.ID, &j.HostID, &j.Target, &j.OSHint, &j.Status, &steps, &j.Error, &j.CreatedBy, &j.CreatedAt, &j.StartedAt, &j.FinishedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(steps, &j.Steps)
	return &j, nil
}

// AppendEnrollmentStep records one step result on a job.
func (s *Store) AppendEnrollmentStep(ctx context.Context, jobID uuid.UUID, step models.EnrollmentStep) error {
	b, _ := json.Marshal(step)
	_, err := s.pool.Exec(ctx,
		`UPDATE enrollment_jobs SET steps = steps || $2::jsonb WHERE id=$1`, jobID, b)
	return err
}

// FinishEnrollmentJob marks a job succeeded/failed/rolled_back with an optional error.
func (s *Store) FinishEnrollmentJob(ctx context.Context, jobID uuid.UUID, status, errMsg string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE enrollment_jobs SET status=$2, error=$3, finished_at=now() WHERE id=$1`, jobID, status, errMsg)
	return err
}

// DeleteFinishedEnrollmentJobs removes every job that is no longer running
// (succeeded/failed/rolled_back), clearing the history on demand while leaving any
// in-progress job in place. Returns the number deleted.
func (s *Store) DeleteFinishedEnrollmentJobs(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM enrollment_jobs WHERE status <> 'running'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// FailStaleEnrollmentJobs marks any still-"running" jobs as failed on startup: an
// enrollment runs inside a request goroutine that does not survive a restart, so a
// job left "running" was interrupted and would otherwise appear stuck forever.
func (s *Store) FailStaleEnrollmentJobs(ctx context.Context, lease time.Duration, self uuid.UUID) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE enrollment_jobs SET status='failed', error='interrupted (owning instance stopped)', finished_at=now()
		 WHERE status='running' AND `+deadOwnerPredicate("enrollment_jobs"), lease.String(), self)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// GetEnrollmentJob loads a job by id.
func (s *Store) GetEnrollmentJob(ctx context.Context, id uuid.UUID) (*models.EnrollmentJob, error) {
	var j models.EnrollmentJob
	var steps []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, host_id, target, os_hint, status, steps, error, created_by, created_at, started_at, finished_at
		FROM enrollment_jobs WHERE id=$1`, id).
		Scan(&j.ID, &j.HostID, &j.Target, &j.OSHint, &j.Status, &steps, &j.Error, &j.CreatedBy, &j.CreatedAt, &j.StartedAt, &j.FinishedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	_ = json.Unmarshal(steps, &j.Steps)
	return &j, nil
}

// ListEnrollmentJobs returns recent enrollment jobs.
func (s *Store) ListEnrollmentJobs(ctx context.Context, limit int) ([]models.EnrollmentJob, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, host_id, target, os_hint, status, steps, error, created_by, created_at, started_at, finished_at
		FROM enrollment_jobs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.EnrollmentJob
	for rows.Next() {
		var j models.EnrollmentJob
		var steps []byte
		if err := rows.Scan(&j.ID, &j.HostID, &j.Target, &j.OSHint, &j.Status, &steps, &j.Error,
			&j.CreatedBy, &j.CreatedAt, &j.StartedAt, &j.FinishedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(steps, &j.Steps)
		out = append(out, j)
	}
	return out, rows.Err()
}

// UsedWGAddresses returns the set of WireGuard addresses already assigned, so
// enrollment can allocate a free one.
func (s *Store) UsedWGAddresses(ctx context.Context) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT host(wg_address) FROM hosts WHERE wg_address IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	used := map[string]bool{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		used[a] = true
	}
	return used, rows.Err()
}

// SetHostWGAddress records the assigned overlay address for a host.
func (s *Store) SetHostWGAddress(ctx context.Context, hostID uuid.UUID, wgAddr string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE hosts SET wg_address=NULLIF($2,'')::inet, updated_at=now() WHERE id=$1`, hostID, wgAddr)
	return err
}

// SetHostOverlay records the reachability transport a host was enrolled with
// (wireguard | openvpn), so re-enrollment and monitoring know which
// overlay the host is on regardless of the current deployment default.
func (s *Store) SetHostOverlay(ctx context.Context, hostID uuid.UUID, overlay string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE hosts SET overlay=$2, updated_at=now() WHERE id=$1`, hostID, overlay)
	return err
}

// SetHostWGPublicKey records a host's WireGuard public key so a standby jump host can
// rebuild the overlay peer list from Postgres on failover.
func (s *Store) SetHostWGPublicKey(ctx context.Context, hostID uuid.UUID, pubKey string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE hosts SET wg_public_key=$2, updated_at=now() WHERE id=$1`, hostID, pubKey)
	return err
}

// WGPeer is one managed host's overlay identity: its WireGuard public key and its
// /32 overlay address (allowed IP on the hub).
type WGPeer struct {
	Hostname  string
	PublicKey string
	Address   string
}

// ListWGPeers returns the overlay peers (hosts with both a WireGuard address and a
// stored public key), so the jump-host hub configuration can be rebuilt from the
// database — used for standby-jump-host failover.
func (s *Store) ListWGPeers(ctx context.Context) ([]WGPeer, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT hostname, wg_public_key, host(wg_address)
		FROM hosts
		WHERE wg_address IS NOT NULL AND wg_public_key <> ''
		ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WGPeer
	for rows.Next() {
		var p WGPeer
		if err := rows.Scan(&p.Hostname, &p.PublicKey, &p.Address); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// WGAddressInUse reports whether wgAddr is already assigned to a host other than
// exceptID (use uuid.Nil to consider all hosts).
func (s *Store) WGAddressInUse(ctx context.Context, wgAddr string, exceptID uuid.UUID) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM hosts WHERE wg_address = $1::inet AND id <> $2`, wgAddr, exceptID).Scan(&n)
	return n > 0, err
}

// wgAllocLockKey is a fixed advisory-lock key (ASCII "WGIP") that serializes
// overlay-address allocation across backend replicas. pg_advisory_xact_lock holds
// it for the life of the enclosing transaction and releases it on commit/rollback,
// so two replicas enrolling different hosts at the same instant take turns reading
// the used set and can never pick the same free address.
const wgAllocLockKey int64 = 0x57474950 // 'W','G','I','P'

// NextFreeWGAddress returns the lowest unused host address in the overlay,
// skipping the jump host's own address. This is a read-only "what would be next"
// probe (used by the UI) and is NOT race-safe on its own: two callers can be
// handed the same address before either persists it. Use ReserveWGAddress to
// atomically allocate AND assign under the allocation lock; the UNIQUE index on
// hosts.wg_address (migration 0075) is the final backstop against a double-assign.
//
// When an overlay subnet CIDR is supplied (e.g. cfg.WGSubnet "10.100.0.0/24" or a
// larger "10.100.0.0/16"), the whole subnet is scanned, so a bigger mask lifts the
// host ceiling accordingly. With no subnet the network is derived from jumpIP as a
// /24 for backward compatibility.
//
// INTEGRATOR: pass the configured overlay subnet as the third argument at every
// call site (cfg.WGSubnet) so the ceiling follows the deployment's mask instead of
// defaulting to /24. The variadic keeps existing 2-arg callers compiling.
func (s *Store) NextFreeWGAddress(ctx context.Context, jumpIP string, subnet ...string) (string, error) {
	used, err := s.UsedWGAddresses(ctx)
	if err != nil {
		return "", err
	}
	return nextFreeWGCandidate(jumpIP, firstOrEmpty(subnet), used)
}

// ReserveWGAddress atomically allocates the next free overlay address and assigns
// it to hostID in a single transaction, serialized across replicas by the overlay
// allocation advisory lock. Because the assignment is written before the lock is
// released, a second replica blocked on the lock reads a used set that already
// includes this address and is guaranteed to pick a different one — concurrent
// replicas can never double-assign. Returns the assigned address.
//
// This is the race-safe path enrollment should use in place of a
// NextFreeWGAddress + SetHostWGAddress pair.
func (s *Store) ReserveWGAddress(ctx context.Context, hostID uuid.UUID, jumpIP string, subnet ...string) (string, error) {
	net := firstOrEmpty(subnet)
	var assigned string
	err := s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, wgAllocLockKey); err != nil {
			return err
		}
		used, err := usedWGAddressesTx(ctx, tx)
		if err != nil {
			return err
		}
		cand, err := nextFreeWGCandidate(jumpIP, net, used)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE hosts SET wg_address=$2::inet, updated_at=now() WHERE id=$1`, hostID, cand); err != nil {
			return err
		}
		assigned = cand
		return nil
	})
	return assigned, err
}

// usedWGAddressesTx reads the assigned overlay addresses inside an open
// transaction (so the read participates in the allocation lock's serialization).
func usedWGAddressesTx(ctx context.Context, tx pgx.Tx) (map[string]bool, error) {
	rows, err := tx.Query(ctx, `SELECT host(wg_address) FROM hosts WHERE wg_address IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	used := map[string]bool{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		used[a] = true
	}
	return used, rows.Err()
}

func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

// nextFreeWGCandidate picks the lowest overlay host address not in used, skipping
// the jump host's address. It is a pure function so the allocation policy is unit
// testable without a database.
//
// With a subnet CIDR it scans the whole IPv4 block (network + broadcast excluded),
// so a /16 offers ~65k addresses vs a /24's ~253 — this is what lifts the
// "hundreds/thousands of hosts" ceiling. With no subnet it falls back to the legacy
// .10–.250 window of the /24 derived from jumpIP.
func nextFreeWGCandidate(jumpIP, subnet string, used map[string]bool) (string, error) {
	jump := strings.TrimSpace(jumpIP)
	if subnet = strings.TrimSpace(subnet); subnet != "" {
		_, ipnet, err := net.ParseCIDR(subnet)
		if err != nil {
			return "", fmt.Errorf("invalid overlay subnet %q: %w", subnet, err)
		}
		return firstFreeInNet(ipnet, jump, used)
	}
	// Legacy path: no configured subnet, assume a /24 around the jump IP.
	parts := strings.Split(jump, ".")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid jump ip %q", jumpIP)
	}
	prefix := strings.Join(parts[:3], ".")
	for n := 10; n <= 250; n++ {
		cand := fmt.Sprintf("%s.%d", prefix, n)
		if cand == jump || used[cand] {
			continue
		}
		return cand, nil
	}
	return "", fmt.Errorf("no free overlay addresses")
}

// maxWGScan bounds how many candidate addresses firstFreeInNet will examine, so a
// mistakenly huge mask (e.g. /8 = 16M hosts) can't turn allocation into a
// multi-second scan. A /16 (65k) — the realistic large-overlay case — is well
// within this bound.
const maxWGScan = 1 << 20

// firstFreeInNet returns the first usable IPv4 host address in ipnet that is
// neither the jump address nor already used. The network and broadcast addresses
// are skipped for any block with room for them (/31 and /32 use every address).
func firstFreeInNet(ipnet *net.IPNet, jump string, used map[string]bool) (string, error) {
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return "", fmt.Errorf("overlay subnet %s is not IPv4", ipnet.String())
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return "", fmt.Errorf("overlay subnet %s is not IPv4", ipnet.String())
	}
	base := binary.BigEndian.Uint32(ip4)
	count := uint64(1) << uint(bits-ones)
	var start, end uint64
	if count <= 2 { // /31, /32: every address is usable
		start, end = 0, count
	} else {
		start, end = 1, count-1 // exclude network + broadcast
	}
	if end-start > maxWGScan {
		end = start + maxWGScan
	}
	for off := start; off < end; off++ {
		var addr [4]byte
		binary.BigEndian.PutUint32(addr[:], base+uint32(off))
		cand := net.IP(addr[:]).String()
		if cand == jump || used[cand] {
			continue
		}
		return cand, nil
	}
	return "", fmt.Errorf("no free overlay addresses in %s", ipnet.String())
}
