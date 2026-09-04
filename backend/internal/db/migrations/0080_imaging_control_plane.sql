-- The imaging control plane, brought in from Flipside and reimplemented against
-- this database (docs/imaging.md).
--
-- Flipside kept these as JSON files because it had no database. Here there is
-- one, with row-level security, backups and an audit trail already attached, so
-- the state belongs in it.

-- A machine as the imaging system knows it.
--
-- Keyed by the identity the imager saw -- usually a MAC address -- because a
-- machine exists to this system *before* it is a host: it is imaged on the
-- provisioning switch, and only later enrolled. That window is real and is why
-- this is not simply a column on `hosts`.
--
-- host_id links the two once both exist. Nullable and ON DELETE SET NULL: a host
-- being removed from inventory does not mean the machine stopped existing, and
-- losing the imaging record with it would lose what the machine was built from.
CREATE TABLE IF NOT EXISTS imaging_machines (
    id            TEXT PRIMARY KEY,
    host_id       UUID REFERENCES hosts(id) ON DELETE SET NULL,
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    hostname      TEXT NOT NULL DEFAULT '',
    address       TEXT NOT NULL DEFAULT '',
    slot          TEXT NOT NULL DEFAULT '',
    version       TEXT NOT NULL DEFAULT '',
    image         TEXT NOT NULL DEFAULT '',
    arch          TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    boot_id       TEXT NOT NULL DEFAULT '',
    health        TEXT NOT NULL DEFAULT '',

    -- What the machine says it is doing about an update it was offered.
    update_state  TEXT NOT NULL DEFAULT 'idle',
    update_error  TEXT NOT NULL DEFAULT '',
    update_rollout TEXT NOT NULL DEFAULT '',

    -- Who last said any of this. A machine's own check-in and an operator's
    -- system reporting what it observed over SSH are different kinds of claim,
    -- and the difference is worth keeping rather than flattening.
    reported_by   TEXT NOT NULL DEFAULT '',
    report_source TEXT NOT NULL DEFAULT 'agent',   -- agent | observed

    -- Operator-owned. Held back means: stays in its groups, keeps reporting,
    -- is never offered an update.
    label         TEXT NOT NULL DEFAULT '',
    held          BOOLEAN NOT NULL DEFAULT false,

    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ,
    imaged_at     TIMESTAMPTZ,
    booted_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_imaging_machines_host ON imaging_machines(host_id);
CREATE INDEX IF NOT EXISTS idx_imaging_machines_seen ON imaging_machines(last_seen DESC NULLS LAST);
-- One machine cannot be two hosts. Partial, because many machines legitimately
-- have no host yet.
CREATE UNIQUE INDEX IF NOT EXISTS idx_imaging_machines_host_unique
    ON imaging_machines(host_id) WHERE host_id IS NOT NULL;

-- A staged rollout of one bundle to a set of machines.
--
-- Targets are Blackfriars host groups, not a grouping of its own. That is the
-- single largest simplification combining the two products buys: there was a
-- set of Flipside groups and a set of Blackfriars groups naming the same machines,
-- and keeping both in step was work nobody would have done.
CREATE TABLE IF NOT EXISTS imaging_rollouts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    bundle        TEXT NOT NULL,
    version       TEXT NOT NULL,
    bundle_url    TEXT NOT NULL DEFAULT '',
    description   TEXT NOT NULL DEFAULT '',

    -- running | paused | halted | completed | cancelled
    state         TEXT NOT NULL DEFAULT 'running',
    halt_reason   TEXT NOT NULL DEFAULT '',

    target_groups UUID[] NOT NULL DEFAULT '{}',
    target_hosts  UUID[] NOT NULL DEFAULT '{}',
    target_all    BOOLEAN NOT NULL DEFAULT false,

    canary        INT NOT NULL DEFAULT 1,
    batch_size    INT NOT NULL DEFAULT 10,
    soak_seconds  INT NOT NULL DEFAULT 900,
    max_failures  INT NOT NULL DEFAULT 2,
    -- Maintenance window in server-local time. NULL means any time.
    window_start  TEXT,
    window_end    TEXT,
    window_days   INT[],

    -- When the canary phase finished. The soak is measured from here and not
    -- from whichever machine verified most recently: timing it from the latter
    -- re-arms the soak as each batch lands, so every batch soaks too, and five
    -- hundred machines in tens with a fifteen-minute soak becomes twelve hours
    -- instead of "prove it on one, then go".
    canary_done_at TIMESTAMPTZ,
    -- Failures counted before the last resume. Resuming means "I have looked at
    -- those; carry on", so the budget starts again from there -- otherwise a
    -- resumed rollout re-halts on the very next heartbeat and `resume` is a
    -- button that returns success and does nothing.
    failure_baseline INT NOT NULL DEFAULT 0,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_by_name TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_imaging_rollouts_state ON imaging_rollouts(state, created_at DESC);

-- One machine's progress through one rollout.
CREATE TABLE IF NOT EXISTS imaging_rollout_machines (
    rollout_id  UUID NOT NULL REFERENCES imaging_rollouts(id) ON DELETE CASCADE,
    machine_id  TEXT NOT NULL REFERENCES imaging_machines(id) ON DELETE CASCADE,
    -- pending | offered | installing | rebooting | verified | failed | skipped
    state       TEXT NOT NULL DEFAULT 'pending',
    error       TEXT NOT NULL DEFAULT '',
    attempts    INT NOT NULL DEFAULT 0,
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (rollout_id, machine_id)
);

CREATE INDEX IF NOT EXISTS idx_imaging_rollout_machines_state
    ON imaging_rollout_machines(rollout_id, state);

-- The provisioning record: what this server handed to a machine, and whether it
-- came back. Append-only; the machine tables above answer "what is true now",
-- and this answers "what did we do and did it work", which a current-state
-- table cannot.
CREATE TABLE IF NOT EXISTS imaging_events (
    id         BIGSERIAL PRIMARY KEY,
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    machine_id TEXT NOT NULL,
    event      TEXT NOT NULL,          -- imaged | booted | offered | installed | failed
    detail     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_imaging_events_machine ON imaging_events(machine_id, created_at DESC);

-- Row-level security, through the helpers 0051 defines rather than by comparing
-- the GUC directly.
--
-- Comparing it directly does not work, and fails in the configuration almost
-- everyone runs. With multi-tenancy off the app sets app.tenant_id='bypass', and
-- `'bypass'::uuid` raises invalid input syntax -- so a direct cast turns every
-- read and every write on these tables into an error, on the default
-- deployment. fleet_rls_visible() handles bypass, an unset value (deny, so a
-- request that forgot to scope fails closed) and a real tenant id.
--
-- fleet_current_tenant() is the matching half for inserts: it resolves the
-- tenant a new row belongs to, including for the background and bypass contexts
-- a machine's heartbeat arrives in. Set as the column DEFAULT so nothing that
-- writes here has to know about tenancy at all.
ALTER TABLE imaging_machines ALTER COLUMN tenant_id SET DEFAULT fleet_current_tenant();
ALTER TABLE imaging_rollouts ALTER COLUMN tenant_id SET DEFAULT fleet_current_tenant();
ALTER TABLE imaging_events   ALTER COLUMN tenant_id SET DEFAULT fleet_current_tenant();

ALTER TABLE imaging_machines ENABLE ROW LEVEL SECURITY;
ALTER TABLE imaging_rollouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE imaging_events   ENABLE ROW LEVEL SECURITY;
-- FORCE, as every other tenant-scoped table has: without it the table owner --
-- which is the application role -- is exempt from its own policy, and the
-- isolation is decorative.
ALTER TABLE imaging_machines FORCE ROW LEVEL SECURITY;
ALTER TABLE imaging_rollouts FORCE ROW LEVEL SECURITY;
ALTER TABLE imaging_events   FORCE ROW LEVEL SECURITY;

-- WITH CHECK as well as USING: USING filters what is read, WITH CHECK
-- constrains what is written. A policy with only USING lets a row be written
-- into another tenant even though it could never be read back.
DROP POLICY IF EXISTS imaging_machines_tenant ON imaging_machines;
CREATE POLICY imaging_machines_tenant ON imaging_machines
    USING (fleet_rls_visible(tenant_id)) WITH CHECK (fleet_rls_visible(tenant_id));

DROP POLICY IF EXISTS imaging_rollouts_tenant ON imaging_rollouts;
CREATE POLICY imaging_rollouts_tenant ON imaging_rollouts
    USING (fleet_rls_visible(tenant_id)) WITH CHECK (fleet_rls_visible(tenant_id));

DROP POLICY IF EXISTS imaging_events_tenant ON imaging_events;
CREATE POLICY imaging_events_tenant ON imaging_events
    USING (fleet_rls_visible(tenant_id)) WITH CHECK (fleet_rls_visible(tenant_id));

-- imaging_rollout_machines has no tenant column of its own: it is reachable
-- only through a rollout, which is scoped, and duplicating the column would be
-- a second place for the two to disagree.
