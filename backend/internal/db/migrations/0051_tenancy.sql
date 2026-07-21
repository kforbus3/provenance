-- Multi-tenancy (MSP) foundation: a tenants table, one seeded provider tenant that all
-- existing data belongs to, and row-level security on every tenant-scoped table so a
-- query is automatically filtered to the caller's tenant. Enforcement is driven by the
-- `app.tenant_id` GUC the app sets per connection (see internal/tenant + internal/db).
--
-- With FLEET_MULTI_TENANCY off the app always sets app.tenant_id='bypass', so the
-- policies below are satisfied for every row and behavior is unchanged. RLS is only
-- actually enforced when (a) the flag is on AND (b) the app connects as a NON-superuser
-- role (Postgres superusers and BYPASSRLS roles ignore RLS even with FORCE).

CREATE TABLE IF NOT EXISTS tenants (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    kind       TEXT NOT NULL DEFAULT 'customer' CHECK (kind IN ('provider','customer')),
    status     TEXT NOT NULL DEFAULT 'active'   CHECK (status IN ('active','suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The seeded provider tenant (the MSP itself). It is also the "default" tenant that all
-- pre-existing rows backfill into, so a single-tenant install simply becomes one
-- provider tenant. Its fixed id is referenced by the app + the RLS helper.
INSERT INTO tenants (id, name, slug, kind)
VALUES ('00000000-0000-0000-0000-000000000001', 'Provider', 'provider', 'provider')
ON CONFLICT (id) DO NOTHING;

-- fleet_current_tenant: the tenant a NEW row belongs to — the request's tenant, or the
-- provider tenant for bypass/background/unset contexts. Used as the tenant_id default.
CREATE OR REPLACE FUNCTION fleet_current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT COALESCE(
    NULLIF(NULLIF(current_setting('app.tenant_id', true), 'bypass'), ''),
    '00000000-0000-0000-0000-000000000001'
  )::uuid
$$;

-- fleet_rls_visible: the row-visibility predicate. 'bypass' sees everything; otherwise a
-- row is visible only when its tenant matches the connection's tenant. An unset/empty
-- setting matches nothing (deny) so a request that forgot to scope fails closed.
CREATE OR REPLACE FUNCTION fleet_rls_visible(tid uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT current_setting('app.tenant_id', true) = 'bypass'
      OR tid::text = current_setting('app.tenant_id', true)
$$;

-- Apply tenant_id + RLS to every tenant-scoped table. tenant_id is added with a CONSTANT
-- default (fast: no table rewrite in PG11+; existing rows -> provider tenant), then the
-- default is swapped to fleet_current_tenant() for future inserts.
DO $$
DECLARE
  t text;
  scoped text[] := ARRAY[
    -- identity / access
    'users','user_credentials','user_roles','user_groups','user_session_policies',
    'mfa_methods','mfa_recovery_codes','api_tokens','groups',
    'approval_requests','temporary_permissions','saved_filters',
    -- hosts + facts
    'hosts','host_groups','host_inventory','host_metrics','host_metrics_history',
    'host_status','host_scans','host_remediations','host_users','host_access_denials',
    'host_fingerprints','windows_software','enrollment_jobs',
    -- sessions + recordings + transfers + certs
    'sessions','ssh_sessions','ssh_certificates','session_recordings','rdp_recordings',
    'session_commands','sftp_transfers',
    -- audit
    'audit_events','auth_events',
    -- automation
    'schedules','playbooks','playbook_versions','playbook_runs',
    'winscripts','winscript_versions','winscript_runs',
    'command_policies','command_approvals','command_runs',
    -- vault
    'vault_secrets','vault_secret_versions','vault_grants','vault_checkouts',
    -- scanning
    'vuln_scans','vuln_findings',
    -- assistant + reviews
    'assistant_actions','access_reviews','access_review_items'
  ];
BEGIN
  FOREACH t IN ARRAY scoped LOOP
    IF to_regclass(t) IS NULL THEN
      CONTINUE; -- table not present in this schema; skip
    END IF;
    EXECUTE format(
      'ALTER TABLE %I ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT ''00000000-0000-0000-0000-000000000001''::uuid',
      t);
    EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET DEFAULT fleet_current_tenant()', t);
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I (tenant_id)', 'idx_' || t || '_tenant', t);
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (fleet_rls_visible(tenant_id)) WITH CHECK (fleet_rls_visible(tenant_id))',
      t);
  END LOOP;
END $$;

-- Provider-tenant management capability. Super Administrator already implies it via the
-- Admin.All wildcard; it is defined so a dedicated provider-admin role can carry it.
INSERT INTO permissions(key, description)
VALUES ('Tenant.Manage', 'Create and administer customer tenants (provider tenant only)')
ON CONFLICT (key) DO NOTHING;
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Tenant.Manage' FROM roles r WHERE r.name = 'Super Administrator'
ON CONFLICT DO NOTHING;
