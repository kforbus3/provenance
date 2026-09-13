-- Rebrand "Fleet Terminal" -> "Provenance" for installs that predate the rename.
-- Fresh installs already seed the current brand (0008). This only touches
-- deployments still on the OLD default and never customized by an admin, so a
-- site that set its own brand name is left untouched.
--
-- The filename keeps its original spelling on purpose: schema_migrations is keyed
-- on it, so renaming the file makes this migration re-run on every existing
-- install. Later brand changes go in their own migration (see 0097).
UPDATE settings
   SET value = '{"app_name":"Provenance"}'
 WHERE key = 'branding'
   AND value::jsonb ->> 'app_name' = 'Fleet Terminal';

-- The System.Upgrade permission description was product-named; refresh it if it
-- still carries the old text.
UPDATE permissions
   SET description = 'Upload and apply Provenance upgrades'
 WHERE key = 'System.Upgrade'
   AND description = 'Upload and apply Fleet Terminal upgrades';
