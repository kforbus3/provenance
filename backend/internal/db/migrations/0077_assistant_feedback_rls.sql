-- Multi-tenancy backfill (follow-up to 0074): scope assistant_feedback.
--
-- assistant_feedback (0069) stores operators' Ask-Fleet questions, the generated
-- answers, and their comments, keyed by user_id. Those questions and answers can
-- reference a tenant's own hosts and activity, so the row is per-tenant data. It was
-- added AFTER the 0074 backfill and therefore shipped with neither a tenant_id column
-- nor an RLS policy — in a FLEET_MULTI_TENANCY deployment one tenant's operators' Ask
-- history and feedback would be visible to another tenant. This closes that gap using
-- the identical idiom as 0074 (constant default first, then fleet_current_tenant();
-- FK to tenants; tenant_id index; ENABLE + FORCE the tenant_isolation policy against
-- fleet_rls_visible()). Single-tenant / non-MT deployments are unaffected: every row
-- backfills to the seeded provider tenant and RLS is transparent to the owner role.

DO $$
DECLARE
  t text;
  scoped text[] := ARRAY[
    'assistant_feedback'  -- 0069 (Ask-Fleet Q&A + feedback, per-tenant; added after 0074)
  ];
BEGIN
 FOREACH t IN ARRAY scoped LOOP
  IF to_regclass(t) IS NULL THEN
    CONTINUE; -- table not present in this schema; skip (idempotent)
  END IF;
  EXECUTE format(
    'ALTER TABLE %I ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT ''00000000-0000-0000-0000-000000000001''::uuid',
    t);
  EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET DEFAULT fleet_current_tenant()', t);
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
