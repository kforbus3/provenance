-- Track the scan/playbook-run records launched by a schedule's most recent fire,
-- so the Schedules page can show whether that run is still in progress. Computed
-- live by checking these records' status; no denormalized state to keep in sync.
ALTER TABLE schedules ADD COLUMN IF NOT EXISTS last_run_ids uuid[] NOT NULL DEFAULT '{}';
