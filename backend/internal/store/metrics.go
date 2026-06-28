package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

// UpsertMetrics writes the latest resource metrics snapshot for a host.
func (s *Store) UpsertMetrics(ctx context.Context, hostID uuid.UUID, m models.HostMetrics) error {
	disk, err := json.Marshal(m.Disk)
	if err != nil || m.Disk == nil {
		disk = []byte("[]")
	}
	net := []byte("{}")
	if m.Network != nil {
		if b, err := json.Marshal(m.Network); err == nil {
			net = b
		}
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO host_metrics (host_id, collected_at, disk, min_disk_free_pct, mem_total_mb,
			mem_available_mb, mem_used_pct, load1, load5, load15, load_per_core, network, primary_ip)
		VALUES ($1, now(), $2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (host_id) DO UPDATE SET
			collected_at=now(), disk=EXCLUDED.disk, min_disk_free_pct=EXCLUDED.min_disk_free_pct,
			mem_total_mb=EXCLUDED.mem_total_mb, mem_available_mb=EXCLUDED.mem_available_mb,
			mem_used_pct=EXCLUDED.mem_used_pct, load1=EXCLUDED.load1, load5=EXCLUDED.load5,
			load15=EXCLUDED.load15, load_per_core=EXCLUDED.load_per_core,
			network=EXCLUDED.network, primary_ip=EXCLUDED.primary_ip`,
		hostID, disk, m.MinDiskFreePct, m.MemTotalMB, m.MemAvailableMB, m.MemUsedPct,
		m.Load1, m.Load5, m.Load15, m.LoadPerCore, net, m.PrimaryIP)
	return err
}

// loadMetrics returns the latest metrics for a host, or nil if none recorded.
func (s *Store) loadMetrics(ctx context.Context, hostID uuid.UUID) *models.HostMetrics {
	var m models.HostMetrics
	var disk, net []byte
	err := s.pool.QueryRow(ctx, `
		SELECT collected_at, disk, min_disk_free_pct, mem_total_mb, mem_available_mb, mem_used_pct,
			load1, load5, load15, load_per_core, network, primary_ip
		FROM host_metrics WHERE host_id=$1`, hostID).
		Scan(&m.CollectedAt, &disk, &m.MinDiskFreePct, &m.MemTotalMB, &m.MemAvailableMB, &m.MemUsedPct,
			&m.Load1, &m.Load5, &m.Load15, &m.LoadPerCore, &net, &m.PrimaryIP)
	if err != nil {
		return nil
	}
	_ = json.Unmarshal(disk, &m.Disk)
	if len(net) > 0 && string(net) != "{}" {
		var n models.HostNetwork
		if json.Unmarshal(net, &n) == nil {
			m.Network = &n
		}
	}
	return &m
}
