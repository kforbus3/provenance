-- Site-as-tenant: a federated site (and its aggregated read-cache + join tokens)
-- belongs to a hub-side tenant, so a multi-tenant hub isolates each provider
-- customer's sites — the Sites list, aggregated inventory, site selector, and proxy
-- are all tenant-scoped. A site inherits the tenant of the operator who minted its
-- join token. Non-multi-tenant deployments are unaffected: the app connects as the
-- table-owner/superuser role and bypasses RLS (same as every other tenant table).
--
-- NOT scoped: the hub identity keys and seen-nonce set (hub-global), and the
-- site-side tables (each site's own single-tenant DB).
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'federation_sites', 'federation_join_tokens',
    'fed_cache_hosts', 'fed_cache_host_status_stats', 'fed_cache_sessions',
    'fed_cache_audit_summary', 'fed_cache_scans', 'fed_cache_schedules',
    'fed_cache_playbook_runs', 'fed_cache_sftp_transfers', 'fed_site_sync_state'
  ] LOOP
    -- Constant default first (fast, no table rewrite; backfills existing rows to the
    -- provider tenant), then switch the default to the request tenant for new rows.
    EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT ''00000000-0000-0000-0000-000000000001''::uuid', t);
    EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET DEFAULT fleet_current_tenant()', t);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_tenant ON %I (tenant_id)', t, t);
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (fleet_rls_visible(tenant_id)) WITH CHECK (fleet_rls_visible(tenant_id))', t);
  END LOOP;
END $$;
