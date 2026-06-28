-- Periodically-collected host resource metrics (disk, memory, load, network),
-- refreshed by the monitor on every probe. One row per host (latest snapshot).

CREATE TABLE IF NOT EXISTS host_metrics (
    host_id           UUID PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    collected_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    disk              JSONB NOT NULL DEFAULT '[]',
    min_disk_free_pct DOUBLE PRECISION,
    mem_total_mb      BIGINT NOT NULL DEFAULT 0,
    mem_available_mb  BIGINT NOT NULL DEFAULT 0,
    mem_used_pct      DOUBLE PRECISION,
    load1             DOUBLE PRECISION,
    load5             DOUBLE PRECISION,
    load15            DOUBLE PRECISION,
    load_per_core     DOUBLE PRECISION,
    network           JSONB NOT NULL DEFAULT '{}',
    primary_ip        TEXT NOT NULL DEFAULT ''
);

-- Supports "hosts with less than N% disk free" style queries.
CREATE INDEX IF NOT EXISTS idx_host_metrics_disk ON host_metrics(min_disk_free_pct);
