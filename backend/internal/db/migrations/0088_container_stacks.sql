-- Container stacks: the desired state of what a host should be running.
--
-- This makes Provenance the source of truth for containers, replacing a git
-- repository plus a renovate bot plus an rsync deploy. The pieces it replaces
-- each did one part of the job and none of them knew what was ACTUALLY running;
-- that half comes from host_inventory.containers, collected over SSH.
--
-- Definitions live here, but the RENDERED file is written to the host as well,
-- and that is deliberate. The break-glass runbook opens by saying Provenance is
-- the single path to your hosts; holding the only copy of every stack definition
-- would make that more true. With a copy on the host, Provenance being down stops
-- you CHANGING what runs, not running it -- which is the property a git checkout
-- on the deploy target was quietly providing.
CREATE TABLE IF NOT EXISTS container_stacks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL DEFAULT prov_current_tenant() REFERENCES tenants(id) ON DELETE CASCADE,
    host_id     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    -- The stack's name, which is also its directory on the host.
    name        TEXT NOT NULL,
    -- The compose file, verbatim. Stored as text rather than parsed: what gets
    -- written to the host must be what was reviewed, and a round trip through a
    -- YAML parser is a chance for those to differ.
    compose     TEXT NOT NULL DEFAULT '',
    -- Where it lives on the host. Defaulted rather than derived so an existing
    -- deployment can be adopted where it already is.
    path        TEXT NOT NULL DEFAULT '',
    -- Bumped on every change. The host records which revision it last applied,
    -- so "deployed" is a comparison rather than an assumption.
    revision    INT NOT NULL DEFAULT 1,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (host_id, name)
);

-- Every change, with who made it and why.
--
-- This replaces `git log`, and it has to: moving desired state out of a
-- repository loses the history that made the repository trustworthy. Keeping the
-- full compose of each revision rather than a diff means a rollback is a copy
-- rather than a reconstruction.
CREATE TABLE IF NOT EXISTS container_stack_revisions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL DEFAULT prov_current_tenant() REFERENCES tenants(id) ON DELETE CASCADE,
    stack_id    UUID NOT NULL REFERENCES container_stacks(id) ON DELETE CASCADE,
    revision    INT NOT NULL,
    compose     TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    author_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    author_name TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (stack_id, revision)
);

-- What the host last confirmed it applied. Separate from the definition so
-- "should be running" and "is running" cannot be conflated -- the mistake that
-- makes a deploy tool lie about its own state.
CREATE TABLE IF NOT EXISTS container_stack_deployments (
    stack_id     UUID PRIMARY KEY REFERENCES container_stacks(id) ON DELETE CASCADE,
    tenant_id    UUID NOT NULL DEFAULT prov_current_tenant() REFERENCES tenants(id) ON DELETE CASCADE,
    revision     INT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'pending',
    detail       TEXT NOT NULL DEFAULT '',
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_stacks_host ON container_stacks(host_id);
CREATE INDEX IF NOT EXISTS idx_stack_revisions_stack ON container_stack_revisions(stack_id, revision DESC);

-- Tenant isolation, the same envelope the rest of the scoped tables use. A stack
-- names a host and carries its configuration, which is tenant data by any
-- reading.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['container_stacks','container_stack_revisions','container_stack_deployments']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I USING (prov_rls_visible(tenant_id)) WITH CHECK (prov_rls_visible(tenant_id))$p$, t);
  END LOOP;
END $$;
