-- Hosts are not independent, and treating them as if they are has broken this
-- fleet twice.
--
-- Provenance models hosts as a flat set. On a real estate they stand on each
-- other: seventeen guests on one hypervisor, every one of their root disks
-- served over NFS by a single NAS. Nothing in the schema could say so, so
-- nothing could act on it.
--
-- What that cost, on the fleet this was written for:
--
--   * An "update apt packages" run covered a group that contained both the
--     guests and the NAS serving their disks. The NAS rebooted mid-run and four
--     guests died on `Timeout waiting for privilege escalation prompt` -- sudo
--     hanging because their root filesystems had gone away. They answered SSH
--     the whole time, so the run recorded unreachable=0 and the failure looked
--     like a sudo problem on four unrelated machines.
--
--   * The workaround is a hand-tuned clock: guests at 03:00, NAS at 03:45,
--     jump host at 04:00, hypervisor at 04:30, with a ten-minute deferred
--     reboot buying the margin. It works, and it is a race that was accepted
--     deliberately -- the guest run is bounded by a ninety-minute timeout, so it
--     CAN still be running when the NAS window opens. Ordering by arithmetic on
--     wall-clock times is the only tool available when the system cannot be told
--     what depends on what.
--
-- This table is that missing fact. It is deliberately small: an edge, a kind,
-- and a note. What reads it comes later -- schedule ordering, and a blast-radius
-- preview before a bulk action -- but neither can be built on a schema that
-- cannot express "these thirteen hosts lose their disks if that one reboots".
--
-- Direction: host_id DEPENDS ON depends_on_host_id. The dependent is the row's
-- subject, because that is the direction every question is asked in -- "what
-- does this host stand on" is answered by the primary key, and "what stands on
-- this host" by the reverse index below.
CREATE TABLE IF NOT EXISTS host_dependencies (
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    depends_on_host_id  UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,

    -- What KIND of dependency, because the consequences differ and an operator
    -- needs to see which one they are looking at:
    --   hypervisor -- depends_on runs this host as a guest. It going down stops
    --                 this host entirely; there is no degraded mode.
    --   storage    -- depends_on serves this host's disks. This host keeps
    --                 answering the network while every write blocks, which is
    --                 why the 2026-08-15 failure did not look like storage.
    --   network    -- depends_on routes or resolves for this host.
    --   other      -- an application-level dependency worth recording.
    kind                TEXT NOT NULL,

    -- Free text for the specific mechanism: "NFS /mnt/p03/vhost_vm_storage over
    -- the 10G link". The kind drives behaviour; this is for the human reading it.
    note                TEXT NOT NULL DEFAULT '',

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    tenant_id           UUID NOT NULL DEFAULT prov_current_tenant(),

    -- One edge per kind. A host can depend on another in more than one way --
    -- a converged box is both hypervisor and storage -- and collapsing those
    -- would lose the distinction that tells an operator what breaks.
    PRIMARY KEY (host_id, depends_on_host_id, kind),

    CONSTRAINT host_dependencies_kind_known
        CHECK (kind IN ('hypervisor', 'storage', 'network', 'other')),

    -- A host cannot stand on itself. Longer cycles are refused in code, where a
    -- useful message can be given; this catches the one case a constraint can.
    CONSTRAINT host_dependencies_not_self
        CHECK (host_id <> depends_on_host_id)
);

-- "What stands on this host" -- the question a blast-radius preview asks, and
-- the expensive direction without an index: one hypervisor has many dependents.
CREATE INDEX IF NOT EXISTS idx_host_dependencies_reverse
    ON host_dependencies (depends_on_host_id);

CREATE INDEX IF NOT EXISTS idx_host_dependencies_tenant
    ON host_dependencies (tenant_id);

-- Tenant-scoped like hosts itself. NOT allowlisted as a child table: a row here
-- names two hosts, so it is the one place a cross-tenant edge could be written,
-- and a dependency graph that can be poisoned across a tenant boundary would let
-- one customer's topology withhold another customer's rollout.
DO $$
BEGIN
  EXECUTE 'ALTER TABLE host_dependencies ENABLE ROW LEVEL SECURITY';
  EXECUTE 'ALTER TABLE host_dependencies FORCE ROW LEVEL SECURITY';
  EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON host_dependencies';
  EXECUTE 'CREATE POLICY tenant_isolation ON host_dependencies USING (prov_rls_visible(tenant_id)) WITH CHECK (prov_rls_visible(tenant_id))';
END $$;

COMMENT ON TABLE host_dependencies IS
  'Which hosts stand on which. host_id depends on depends_on_host_id; kind says how.';
