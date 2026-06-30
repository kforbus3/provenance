-- Pending package updates per host, collected by the monitor alongside facts.
-- NULL means "not yet checked / unknown" (distinct from 0 = up to date).

ALTER TABLE host_inventory ADD COLUMN IF NOT EXISTS updates_available  INT;
ALTER TABLE host_inventory ADD COLUMN IF NOT EXISTS security_updates   INT;
ALTER TABLE host_inventory ADD COLUMN IF NOT EXISTS updates_checked_at TIMESTAMPTZ;
