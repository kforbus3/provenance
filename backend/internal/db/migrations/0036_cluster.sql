-- Cluster instance registry for High Availability. Each running backend process
-- registers a row at boot (with a fresh id — a restart is a NEW instance, since its
-- in-RAM sessions/certs did not survive) and heartbeats it. Liveness is derived from
-- last_heartbeat: an instance whose heartbeat is older than the lease is considered
-- dead, which drives ownership-scoped reconciliation of the work it was running.
--
-- Leadership itself is NOT stored here — it is held via a Postgres session-scoped
-- advisory lock, which auto-releases if the leader's connection drops (split-brain
-- free). This table is for identity, liveness, and observability.
CREATE TABLE IF NOT EXISTS cluster_instances (
    id             UUID PRIMARY KEY,
    hostname       TEXT NOT NULL DEFAULT '',
    version        TEXT NOT NULL DEFAULT '',
    is_leader      BOOLEAN NOT NULL DEFAULT false,
    started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cluster_instances_heartbeat ON cluster_instances(last_heartbeat);
