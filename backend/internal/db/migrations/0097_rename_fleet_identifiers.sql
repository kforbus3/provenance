-- Rename the last database identifiers that carried the old product name.
--
-- Every statement is guarded, because two populations reach this migration:
--   * an existing install, where 0051/0034/0031 created fleet_-prefixed objects
--     and rows hold 'fleet_cert';
--   * a fresh install, where those same migrations now create the prov_ names
--     directly, so there is nothing here to rename.
-- Both must end on exactly the same schema — docs/deployment.md §8 pins that
-- with a byte-comparison of the two paths.

-- 1. The RLS helpers. ~80 tables carry `DEFAULT fleet_current_tenant()` and every
-- row-level-security policy calls fleet_rls_visible(); both reference the function
-- by OID, so the rename propagates to the stored defaults and policies without
-- touching them individually. 0097_test verifies that rather than trusting it.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'public' AND p.proname = 'fleet_current_tenant') THEN
    ALTER FUNCTION public.fleet_current_tenant() RENAME TO prov_current_tenant;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'public' AND p.proname = 'fleet_rls_visible') THEN
    ALTER FUNCTION public.fleet_rls_visible(uuid) RENAME TO prov_rls_visible;
  END IF;
END $$;

-- 2. rdp_recordings.fleet_user — the Provenance-side operator, as distinct from
-- the RDP account they logged in as.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
              WHERE table_schema = 'public' AND table_name = 'rdp_recordings'
                AND column_name = 'fleet_user') THEN
    ALTER TABLE rdp_recordings RENAME COLUMN fleet_user TO prov_user;
  END IF;
END $$;

-- 3. hosts.auth_method is a stored VALUE, not just a default, so the rows move too.
ALTER TABLE hosts ALTER COLUMN auth_method SET DEFAULT 'prov_cert';
UPDATE hosts SET auth_method = 'prov_cert' WHERE auth_method = 'fleet_cert';

-- 4. hosts.ssh_user: only the default changes. Existing rows name the account that
-- actually exists on each host right now, and moving a host to the new account is a
-- deliberate, verified operation the application performs over SSH
-- (Hosts -> host -> Migrate login account). Rewriting these rows here would strand
-- every enrolled host: the row would name an account sshd has never heard of.
ALTER TABLE hosts ALTER COLUMN ssh_user SET DEFAULT 'prov';

-- 5. Brand text in seeded data. 0008 seeds the current name for fresh installs and
-- 0078 moved pre-rename installs off "Fleet Terminal"; neither knows about the names
-- the product has had since. Only ever touch a value still equal to an old default,
-- so an operator who set their own brand keeps it.
UPDATE settings
   SET value = '{"app_name":"Provenance"}'
 WHERE key = 'branding'
   AND value::jsonb ->> 'app_name' IN ('Fleet Terminal', 'Moorgate', 'Blackfriars');

UPDATE permissions
   SET description = 'Upload and apply Provenance upgrades'
 WHERE key = 'System.Upgrade'
   AND description IN ('Upload and apply Fleet Terminal upgrades',
                       'Upload and apply Moorgate upgrades',
                       'Upload and apply Blackfriars upgrades');
