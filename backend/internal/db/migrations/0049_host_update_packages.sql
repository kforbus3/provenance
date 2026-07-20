-- Per-host pending update package list (package name, target version, security flag),
-- collected by the monitor alongside the update COUNTS in 0014. NULL = not yet
-- collected. Stored as JSONB and replaced atomically on each check; the collector caps
-- the list so a host with thousands of pending updates can't bloat the row.
ALTER TABLE host_inventory ADD COLUMN IF NOT EXISTS update_packages JSONB;
