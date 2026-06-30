-- Scheduling: recurring scans and playbook runs configured in the UI. Schedules
-- are disabled by default; an operator enables one explicitly. A background
-- engine fires due, enabled schedules by reusing the normal scan/playbook run
-- paths, so their results appear in the usual history.

INSERT INTO permissions(key, description) VALUES
    ('Schedule.Manage', 'Create and manage scheduled scans and playbook runs')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Schedule.Manage' FROM roles r WHERE r.name = 'Administrator'
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS schedules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,                       -- scan | playbook
    enabled     BOOLEAN NOT NULL DEFAULT false,
    target_kind TEXT NOT NULL DEFAULT 'host',        -- host | group
    target_id   UUID,                                -- host id or group id
    target_name TEXT NOT NULL DEFAULT '',
    recurrence  JSONB NOT NULL DEFAULT '{}',         -- {type, everyMinutes, timeOfDay, weekday}
    payload     JSONB NOT NULL DEFAULT '{}',         -- scan or playbook parameters
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    requester   TEXT NOT NULL DEFAULT '',
    last_run_at TIMESTAMPTZ,
    last_status TEXT NOT NULL DEFAULT '',
    next_run_at TIMESTAMPTZ,                          -- NULL when disabled
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_schedules_due ON schedules(next_run_at) WHERE enabled;
