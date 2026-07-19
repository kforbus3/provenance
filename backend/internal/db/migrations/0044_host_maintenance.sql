-- Maintenance windows: when maintenance_until is set to a future time, the host is
-- "in maintenance" and its offline/recovered alerts and dashboard "needs attention"
-- items are suppressed (e.g. while patching or rebooting). Cleared by setting NULL
-- or letting the timestamp pass.

ALTER TABLE hosts ADD COLUMN IF NOT EXISTS maintenance_until TIMESTAMPTZ;
