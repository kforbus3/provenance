-- Remember which rules a scan skipped (oscap --skip-rule), so a remediation
-- re-scan can reuse the same exclusions instead of running the full profile.
ALTER TABLE host_scans ADD COLUMN IF NOT EXISTS skip_rules TEXT[] NOT NULL DEFAULT '{}';
