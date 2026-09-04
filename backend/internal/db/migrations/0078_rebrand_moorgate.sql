-- Rebrand "Fleet Terminal" -> "Blackfriars" for installs that predate the rename.
-- Fresh installs already seed "Blackfriars" (0008). This only touches deployments
-- still on the OLD default and never customized by an admin, so a site that set
-- its own brand name is left untouched.
UPDATE settings
   SET value = '{"app_name":"Blackfriars"}'
 WHERE key = 'branding'
   AND value::jsonb ->> 'app_name' = 'Fleet Terminal';

-- The System.Upgrade permission description was product-named; refresh it if it
-- still carries the old text.
UPDATE permissions
   SET description = 'Upload and apply Blackfriars upgrades'
 WHERE key = 'System.Upgrade'
   AND description = 'Upload and apply Fleet Terminal upgrades';
