-- Ownership tags for long-running work, so boot/periodic reconciliation can fail
-- only the rows whose owning instance is no longer alive (HA), instead of the
-- pre-HA behaviour of failing every "active"/"running" row on any restart — which
-- in a multi-instance deployment would kill a live peer's sessions and jobs.
--
-- instance_id references the cluster_instances row of the backend that owns the
-- in-RAM work (the live PTY, or the goroutine running the scan/playbook). NULL means
-- unknown/legacy (pre-HA rows), which reconciliation treats as unowned → stale.
ALTER TABLE ssh_sessions      ADD COLUMN IF NOT EXISTS instance_id UUID;
ALTER TABLE rdp_recordings    ADD COLUMN IF NOT EXISTS instance_id UUID;
ALTER TABLE host_scans        ADD COLUMN IF NOT EXISTS instance_id UUID;
ALTER TABLE vuln_scans        ADD COLUMN IF NOT EXISTS instance_id UUID;
ALTER TABLE host_remediations ADD COLUMN IF NOT EXISTS instance_id UUID;
ALTER TABLE playbook_runs     ADD COLUMN IF NOT EXISTS instance_id UUID;
ALTER TABLE enrollment_jobs   ADD COLUMN IF NOT EXISTS instance_id UUID;
