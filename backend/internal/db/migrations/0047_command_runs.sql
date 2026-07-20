-- Ad-hoc command runner: run a one-off shell command on one or more Linux (SSH)
-- hosts without authoring a playbook — the lightweight counterpart to Ansible
-- playbooks and PowerShell scripts. Each run's per-host output is aggregated into
-- one record (like winscript_runs). Execution is governed by the command-control
-- policy (flag/block/approval) exactly as an interactive session would be.
CREATE TABLE IF NOT EXISTS command_runs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    command      TEXT NOT NULL,
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    requester    TEXT NOT NULL DEFAULT '',
    target_kind  TEXT NOT NULL DEFAULT 'host',   -- host | group
    target_id    UUID,                            -- host id or group id
    target_name  TEXT NOT NULL DEFAULT '',
    host_count   INT  NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'pending', -- pending | running | completed | failed
    exit_code    INT,
    output       TEXT NOT NULL DEFAULT '',
    error        TEXT NOT NULL DEFAULT '',
    instance_id  UUID,                            -- HA: which backend instance owns the in-flight run
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_command_runs_created ON command_runs(created_at DESC);

-- Command.Run gates executing ad-hoc commands. Administrator-only by default,
-- mirroring Script.Run / Playbook.Run; grant to Operator explicitly if desired.
INSERT INTO permissions(key, description) VALUES
    ('Command.Run', 'Run ad-hoc shell commands on managed Linux hosts')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Command.Run' FROM roles r WHERE r.name IN ('Super Administrator', 'Administrator')
ON CONFLICT DO NOTHING;
