package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

// MetricHistoryPoint is one time bucket of a host's metric history: averages plus
// the worst-case extreme in the bucket (min free disk, max memory used, max load),
// which is what makes a trend readable ("free disk fell from 40% to 12%").
type MetricHistoryPoint struct {
	Time           time.Time `json:"t"`
	Samples        int       `json:"samples"`
	DiskFreePctAvg *float64  `json:"diskFreePctAvg,omitempty"`
	DiskFreePctMin *float64  `json:"diskFreePctMin,omitempty"`
	MemUsedPctAvg  *float64  `json:"memUsedPctAvg,omitempty"`
	MemUsedPctMax  *float64  `json:"memUsedPctMax,omitempty"`
	LoadPerCoreAvg *float64  `json:"loadPerCoreAvg,omitempty"`
	LoadPerCoreMax *float64  `json:"loadPerCoreMax,omitempty"`
}

// RecordMetricHistory appends a scalar metrics sample for a host, but only if the
// most recent sample is older than sample — so the append-only series stays at the
// configured cadence regardless of the (more frequent) probe interval. The throttle
// is a single atomic INSERT ... WHERE NOT EXISTS, so no read-modify-write race.
func (s *Store) RecordMetricHistory(ctx context.Context, hostID uuid.UUID, m models.HostMetrics, sample time.Duration) error {
	secs := sample.Seconds()
	if secs < 0 {
		secs = 0
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO host_metrics_history (host_id, min_disk_free_pct, mem_used_pct, load_per_core)
		SELECT $1, $2, $3, $4
		WHERE NOT EXISTS (
			SELECT 1 FROM host_metrics_history
			WHERE host_id = $1 AND collected_at > now() - make_interval(secs => $5))`,
		hostID, m.MinDiskFreePct, m.MemUsedPct, m.LoadPerCore, secs)
	return err
}

// PruneMetricHistoryBefore deletes samples collected before cutoff, returning the
// number removed. Called by the retention loop.
func (s *Store) PruneMetricHistoryBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM host_metrics_history WHERE collected_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// MetricHistory returns a host's metric samples since `since`, aggregated into
// fixed-width time buckets of bucket duration (one row per non-empty bucket, in
// chronological order). Bucketing keeps the series compact enough to hand to the
// model even for wide windows. Buckets with no samples are simply absent.
func (s *Store) MetricHistory(ctx context.Context, hostID uuid.UUID, since time.Time, bucket time.Duration) ([]MetricHistoryPoint, error) {
	bucketSecs := bucket.Seconds()
	if bucketSecs < 1 {
		bucketSecs = 1
	}
	rows, err := s.pool.Query(ctx, `
		SELECT
			to_timestamp(floor(extract(epoch from collected_at) / $3) * $3) AS bucket,
			count(*),
			avg(min_disk_free_pct), min(min_disk_free_pct),
			avg(mem_used_pct),      max(mem_used_pct),
			avg(load_per_core),     max(load_per_core)
		FROM host_metrics_history
		WHERE host_id = $1 AND collected_at >= $2
		GROUP BY bucket
		ORDER BY bucket`, hostID, since, bucketSecs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MetricHistoryPoint
	for rows.Next() {
		var p MetricHistoryPoint
		if err := rows.Scan(&p.Time, &p.Samples,
			&p.DiskFreePctAvg, &p.DiskFreePctMin,
			&p.MemUsedPctAvg, &p.MemUsedPctMax,
			&p.LoadPerCoreAvg, &p.LoadPerCoreMax); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
