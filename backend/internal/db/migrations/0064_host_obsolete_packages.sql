-- Track the set of "obsolete" packages on each host: installed, but offered by no
-- configured repository (apt's [installed,local] / dnf "extras"). These are almost
-- always orphaned leftovers from in-place distribution upgrades. A vulnerability
-- finding whose package is in this set cannot be fixed by an update — the fix is to
-- REMOVE the package — so the assistant and UI can label it accordingly instead of
-- showing a misleading "fixable".
ALTER TABLE host_inventory ADD COLUMN IF NOT EXISTS obsolete_packages JSONB;
