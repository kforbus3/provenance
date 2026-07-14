-- Append-only time series of host resource metrics, so the assistant (and future
-- charts) can answer trend questions like "disk usage on web-01 over the past
-- 48h". host_metrics keeps only the latest snapshot (one row per host, overwritten
-- each probe); this table retains scalar samples over time. Only the scalars useful
-- for trends are kept (not the full per-filesystem/network JSONB) so rows stay small.
-- Sampling cadence and retention are bounded by the app (FLEET_METRIC_HISTORY_SAMPLE
-- / FLEET_METRIC_HISTORY_RETENTION); old rows are pruned by the retention loop.

CREATE TABLE IF NOT EXISTS host_metrics_history (
    host_id           UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    collected_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    min_disk_free_pct DOUBLE PRECISION,
    mem_used_pct      DOUBLE PRECISION,
    load_per_core     DOUBLE PRECISION
);

-- Serves both the per-host windowed range scan (trend queries) and the
-- throttle check ("is there already a sample in the last N minutes for this host").
CREATE INDEX IF NOT EXISTS idx_host_metrics_history_host_time
    ON host_metrics_history (host_id, collected_at DESC);
