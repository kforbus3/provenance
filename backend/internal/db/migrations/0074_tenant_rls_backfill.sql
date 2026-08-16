-- Multi-tenancy backfill: extend row-level security to tenant-scoped tables that were
-- added AFTER the tenancy foundation (0051) / federation-tenancy (0062) and therefore
-- shipped with NEITHER a tenant_id column NOR an RLS policy. Until this migration, in a
-- FLEET_MULTI_TENANCY deployment a customer-tenant admin could read/edit/delete EVERY
-- tenant's rows in these tables (they were not filtered by app.tenant_id at all).
--
-- This mirrors 0051 exactly: add tenant_id with a CONSTANT default first (fast — no table
-- rewrite in PG11+; existing rows backfill to the seeded provider tenant
-- 00000000-0000-0000-0000-000000000001), then swap the default to fleet_current_tenant()
-- so future inserts pick up the connection's tenant from the app.tenant_id GUC, add a
-- FK to tenants + a tenant_id index, and ENABLE + FORCE the same tenant_isolation policy
-- (USING and WITH CHECK against fleet_rls_visible()). The helper functions
-- fleet_current_tenant() / fleet_rls_visible() and the provider tenant come from 0051.
--
-- With the flag OFF the app always sets app.tenant_id='bypass', so every policy below is
-- satisfied and behavior is unchanged; RLS only bites when (a) the flag is on AND (b) the
-- app connects as a NON-superuser, NOBYPASSRLS role (see db.verifyRLSCapableRole).
--
-- PER-TABLE DECISIONS (tenant-scoped vs. fleet-global) --------------------------------
--   TENANT-SCOPED (get tenant_id + FORCE RLS below):
--     * databases        (0053) — a registered SQL target belongs to one customer.
--     * access_policies  (0056) — ABAC rules are authored per customer tenant.
--     * k8s_clusters      (0057) — a registered cluster target belongs to one customer.
--     * vuln_sboms       (0071) — a host SBOM is a per-host artifact, and hosts are
--                                 tenant-scoped (vuln_scans/vuln_findings already are in
--                                 0051), so its SBOMs must be too. Guarded by to_regclass:
--                                 scoped when the table is present, skipped otherwise
--                                 (this branch may predate the 0071 migration).
--     * external_secrets  (0058) — see note: in this schema there is NO external_secrets
--                                 TABLE; the "external secrets" feature is two columns
--                                 (external_provider, external_ref) on vault_secrets,
--                                 which 0051 ALREADY tenant-scopes + FORCE-RLSes. So the
--                                 external-secret material is already isolated and there
--                                 is nothing to add. The name is still listed in the loop
--                                 with a to_regclass guard so that, if a deployment ever
--                                 does grow a real external_secrets table, it is scoped
--                                 rather than silently unprotected. Today the guard skips.
--
--   INTENTIONALLY FLEET-GLOBAL (deliberately NOT scoped — documented so a future
--   "every table must have RLS" CI check has an explicit, reasoned allowlist):
--     * ssh_host_keys      (0068) — TOFU host-key pins are the cryptographic identity of a
--                                 physical host (PRIMARY KEY host), shared infrastructure
--                                 state for the single gateway process; 0068 already states
--                                 this table is intentionally not tenant-scoped. Scoping it
--                                 would demand a composite key AND would let a hostile
--                                 tenant re-pin a host another tenant reaches — weakening,
--                                 not strengthening, isolation. Kept global.
--     * overlay_revocations (0073) — the overlay PKI (overlay_ca/overlay_clients, 0049) is
--                                 a single fleet-wide CA/CRL used only in FIPS/OpenVPN
--                                 overlay mode and is NOT in 0051's scoped set; the
--                                 revocation list is consumed by the overlay server as one
--                                 global CRL. Partitioning it per tenant would be wrong and
--                                 could let a tenant hide a revocation. Kept global,
--                                 consistent with the rest of the overlay PKI.
--
-- CI NOTE (no CI written here — another agent owns .github): a check that every new table
-- carries tenant_id + FORCE RLS should treat ssh_host_keys and overlay_revocations as the
-- documented, reasoned exceptions above; every other tenant-data table must be scoped.
-- -------------------------------------------------------------------------------------

DO $$
DECLARE
  t text;
  scoped text[] := ARRAY[
    'databases',         -- 0053
    'access_policies',   -- 0056
    'k8s_clusters',      -- 0057
    'external_secrets',  -- 0058 (no such table today; feature lives on vault_secrets — guard skips it)
    'vuln_sboms'         -- 0071 (present only once that migration has run; guard skips it otherwise)
  ];
BEGIN
  FOREACH t IN ARRAY scoped LOOP
    IF to_regclass(t) IS NULL THEN
      CONTINUE; -- table not present in this schema; skip (idempotent + forward-compatible)
    END IF;
    -- Constant default first (fast, no table rewrite; existing rows -> provider tenant),
    -- then switch the default to the request tenant for new rows.
    EXECUTE format(
      'ALTER TABLE %I ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT ''00000000-0000-0000-0000-000000000001''::uuid',
      t);
    EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET DEFAULT fleet_current_tenant()', t);
    -- Add the FK to tenants (idempotently — ADD CONSTRAINT has no IF NOT EXISTS).
    IF NOT EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conrelid = to_regclass(t) AND conname = t || '_tenant_id_fkey'
    ) THEN
      EXECUTE format(
        'ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (tenant_id) REFERENCES tenants(id)',
        t, t || '_tenant_id_fkey');
    END IF;
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I (tenant_id)', 'idx_' || t || '_tenant', t);
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (fleet_rls_visible(tenant_id)) WITH CHECK (fleet_rls_visible(tenant_id))',
      t);
  END LOOP;
END $$;
