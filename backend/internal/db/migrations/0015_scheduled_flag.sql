-- Distinguish scheduled runs from manual ones, so they can be reported and
-- filtered separately (e.g. in the AI assistant).

ALTER TABLE host_scans    ADD COLUMN IF NOT EXISTS scheduled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE playbook_runs ADD COLUMN IF NOT EXISTS scheduled BOOLEAN NOT NULL DEFAULT false;
