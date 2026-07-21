package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
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
func (s *Store) FailStaleEnrollmentJobs(ctx context.Context, lease time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE enrollment_jobs SET status='failed', error='interrupted (owning instance stopped)', finished_at=now()
		 WHERE status='running' AND `+deadOwnerPredicate("enrollment_jobs"), lease.String())
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

// NextFreeWGAddress returns the lowest unused /24 host address in the overlay
// whose network is derived from jumpIP, skipping the jump host's own address.
func (s *Store) NextFreeWGAddress(ctx context.Context, jumpIP string) (string, error) {
	used, err := s.UsedWGAddresses(ctx)
	if err != nil {
		return "", err
	}
	parts := strings.Split(strings.TrimSpace(jumpIP), ".")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid jump ip %q", jumpIP)
	}
	prefix := strings.Join(parts[:3], ".")
	for n := 10; n <= 250; n++ {
		cand := fmt.Sprintf("%s.%d", prefix, n)
		if cand == jumpIP || used[cand] {
			continue
		}
		return cand, nil
	}
	return "", fmt.Errorf("no free overlay addresses")
}
