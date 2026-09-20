-- Bring the fleet_ -> prov_ rename of the RLS helpers FORWARD, ahead of the first
-- migration that depends on the new names.
--
-- 0051_tenancy.sql was edited in place during the rename: it used to create
-- fleet_current_tenant()/fleet_rls_visible() and now creates the prov_ names. A
-- migration is recorded by version and applied once, so that edit reaches a fresh
-- install and never reaches one that had already applied 0051.
--
-- 0097_rename_fleet_identifiers exists to converge those two populations and does it
-- correctly — but it runs at 0097, and SEVEN migrations between 0051 and 0097 need the
-- prov_ names before then. They fail in two different ways, and the quiet one is worse:
--
--   * 0074_tenant_rls_backfill references prov_current_tenant() directly and stops the
--     upgrade dead — ERROR: function prov_current_tenant() does not exist (42883). That
--     is why every release bundle's minFromVersion of 0.0.0 was untrue for any database
--     predating the rename.
--   * 0062, 0063, 0077, 0080, 0088 and 0090 wrap their tenant work in
--     IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'prov_current_tenant'), so on an
--     upgrade path they SKIP it and say nothing. host_status_events came out of that
--     with no tenant_id, no index and no policy — a table that is simply not isolated,
--     on a deployment that believes it is.
--
-- So this runs immediately after 0051, where the names are established, rather than at
-- the point of the first hard failure. Found by migrating a v0.55.5 schema forward and
-- diffing it against a fresh install of the same version.
--
-- This does exactly what 0097 does, just early enough to matter. RENAME rather than
-- CREATE, deliberately: creating the prov_ name while the fleet_ one still exists
-- leaves two functions, and 0097 then fails collidingly when it tries to rename the old
-- one over the new. Renaming also carries the ~80 stored column defaults and every RLS
-- policy with it, because they reference the function by OID.
--
-- Guarded on both sides, so it is a no-op on a fresh install (nothing to rename) and on
-- one that has already been through 0097 (nothing left named fleet_).

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'public' AND p.proname = 'fleet_current_tenant')
     AND NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'public' AND p.proname = 'prov_current_tenant') THEN
    ALTER FUNCTION public.fleet_current_tenant() RENAME TO prov_current_tenant;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'public' AND p.proname = 'fleet_rls_visible')
     AND NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'public' AND p.proname = 'prov_rls_visible') THEN
    ALTER FUNCTION public.fleet_rls_visible(uuid) RENAME TO prov_rls_visible;
  END IF;
END $$;
