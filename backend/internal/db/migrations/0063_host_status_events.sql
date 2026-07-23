-- Host availability history. The monitor already ALERTS on an online<->offline
-- transition (notify.EventHostOffline/Recovered) but nothing persisted it, so a
-- host that went down and recovered between page refreshes left no queryable
-- trace — "did anything go offline overnight?" was unanswerable. Each row records
-- one status transition; downtime is reconstructed by pairing an offline event
-- with the next recovery.
CREATE TABLE IF NOT EXISTS host_status_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    from_status TEXT NOT NULL,
    to_status   TEXT NOT NULL,
    last_error  TEXT NOT NULL DEFAULT '',
    at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Availability queries are "events for this host, newest first" and "all events in
-- the last N hours"; index both access paths.
CREATE INDEX IF NOT EXISTS idx_host_status_events_host_time ON host_status_events (host_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_host_status_events_time ON host_status_events (at DESC);

-- Apply the same tenant_id + row-level-security envelope the other per-host tables
-- carry (functions fleet_current_tenant/fleet_rls_visible are defined in 0051). With
-- FLEET_MULTI_TENANCY off the app sets app.tenant_id='bypass' and every row is
-- visible; with it on, a tenant sees only its own hosts' availability history.
DO $$
BEGIN
  IF to_regclass('host_status_events') IS NOT NULL
     AND EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'fleet_current_tenant')
     AND EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'fleet_rls_visible') THEN
    ALTER TABLE host_status_events ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001'::uuid;
    ALTER TABLE host_status_events ALTER COLUMN tenant_id SET DEFAULT fleet_current_tenant();
    CREATE INDEX IF NOT EXISTS idx_host_status_events_tenant ON host_status_events (tenant_id);
    ALTER TABLE host_status_events ENABLE ROW LEVEL SECURITY;
    ALTER TABLE host_status_events FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation ON host_status_events;
    CREATE POLICY tenant_isolation ON host_status_events
        USING (fleet_rls_visible(tenant_id)) WITH CHECK (fleet_rls_visible(tenant_id));
  END IF;
END $$;
