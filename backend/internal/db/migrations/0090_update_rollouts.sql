-- Staged rollouts of a container image update.
--
-- The same shape as an imaging rollout, and deliberately so: an operator says
-- "move nginx:1.24 to 1.27, one host first, then five at a time, and stop if two
-- fail", and the rules that pace it are the ones in internal/pacing that image
-- rollouts already obey. A second set of pacing rules would drift from the first,
-- and the drift would only show up as "the whole fleet took the bad version".
--
-- Unlike an imaging rollout this one PUSHES: there is no agent checking in, so a
-- tick of the engine reaches the hosts it has capacity for. That changes who
-- starts the work, not the rules about when it may start.
CREATE TABLE IF NOT EXISTS container_update_rollouts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL DEFAULT prov_current_tenant() REFERENCES tenants(id) ON DELETE CASCADE,

    repository    TEXT NOT NULL,
    -- The tag hosts are on now, and the one they are moving to. They are equal
    -- when only the DIGEST moved -- a rebuild of the same version -- which is a
    -- real update with nothing to rewrite in the compose file, and the reason
    -- the deploy must pull rather than trust `up -d`.
    from_tag      TEXT NOT NULL,
    to_tag        TEXT NOT NULL,
    -- What the registry said the target points at when the rollout was created.
    -- A host is verified against THIS, not against whatever the tag points at by
    -- the time the host is reached: a tag that moves mid-rollout would otherwise
    -- leave the early hosts on bytes the late ones never get, with every host
    -- reported as verified.
    target_digest TEXT NOT NULL DEFAULT '',

    state         TEXT NOT NULL DEFAULT 'running',
    halt_reason   TEXT NOT NULL DEFAULT '',

    canary        INT NOT NULL DEFAULT 1,
    batch_size    INT NOT NULL DEFAULT 5,
    soak_seconds  INT NOT NULL DEFAULT 900,
    max_failures  INT NOT NULL DEFAULT 1,

    window_start  TEXT,
    window_end    TEXT,
    window_days   INT[],

    -- When the canary phase finished. The soak is measured from here, not from
    -- whichever host finished most recently -- the latter re-arms the soak as
    -- each batch lands, so every batch soaks and a large fleet never finishes.
    canary_done_at TIMESTAMPTZ,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL
);

-- One host's place in one rollout.
CREATE TABLE IF NOT EXISTS container_update_rollout_hosts (
    rollout_id  UUID NOT NULL REFERENCES container_update_rollouts(id) ON DELETE CASCADE,
    host_id     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    -- pending | applying | verified | failed | skipped
    state       TEXT NOT NULL DEFAULT 'pending',
    error       TEXT NOT NULL DEFAULT '',
    attempts    INT NOT NULL DEFAULT 0,
    -- Failures counted before the last resume. Resuming means "I have looked at
    -- those, carry on", so the budget starts again from here -- without it a
    -- rollout that halted on its budget re-halts on the next tick and `resume`
    -- becomes a button that reports success and does nothing.
    forgiven    BOOLEAN NOT NULL DEFAULT FALSE,
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (rollout_id, host_id)
);

CREATE INDEX IF NOT EXISTS idx_update_rollouts_state ON container_update_rollouts(state);
CREATE INDEX IF NOT EXISTS idx_update_rollout_hosts_state
    ON container_update_rollout_hosts(rollout_id, state);

-- Tenant isolation. A rollout names hosts and drives changes onto them, which is
-- tenant data by any reading.
--
-- The per-host progress table carries no tenant_id of its own: it is reachable
-- only through its rollout, which is scoped, and a second copy of the parent's
-- tenant would be a second place for the two to disagree. Same reasoning as
-- imaging_rollout_machines (0080).
DO $$
BEGIN
  EXECUTE 'ALTER TABLE container_update_rollouts ENABLE ROW LEVEL SECURITY';
  EXECUTE 'ALTER TABLE container_update_rollouts FORCE ROW LEVEL SECURITY';
  EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON container_update_rollouts';
  EXECUTE 'CREATE POLICY tenant_isolation ON container_update_rollouts USING (prov_rls_visible(tenant_id)) WITH CHECK (prov_rls_visible(tenant_id))';
END $$;
