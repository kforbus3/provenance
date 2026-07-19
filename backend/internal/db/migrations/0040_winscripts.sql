-- PowerShell script management for Windows (RDP) hosts: the Windows counterpart to
-- Ansible playbooks. Author/edit scripts in the UI, then run them on Windows hosts
-- over WinRM (the same transport the monitor uses for facts), authenticated with the
-- host's vaulted credential (honoring its check-out policy).
--
-- Two permissions, both Administrator-only by default, mirroring Playbook.Edit/Run:
--   Script.Edit -- author, edit, delete PowerShell scripts.
--   Script.Run  -- run a script on Windows hosts (executes arbitrary code as the
--                  host's credentialed user); granted separately on purpose.

INSERT INTO permissions(key, description) VALUES
    ('Script.Edit', 'Author, edit, and delete PowerShell scripts'),
    ('Script.Run',  'Run PowerShell scripts on Windows hosts (executes changes on hosts)')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, p.key
FROM roles r
CROSS JOIN (VALUES ('Script.Edit'), ('Script.Run')) AS p(key)
WHERE r.name = 'Administrator'
ON CONFLICT DO NOTHING;

-- A PowerShell script: a single document plus metadata. `version` bumps on each
-- content change; the prior content is snapshotted into winscript_versions.
CREATE TABLE IF NOT EXISTS winscripts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    content     TEXT NOT NULL DEFAULT '',
    version     INT  NOT NULL DEFAULT 1,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_winscripts_name ON winscripts(lower(name));

-- Immutable revision history so edits are auditable and recoverable.
CREATE TABLE IF NOT EXISTS winscript_versions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    script_id   UUID NOT NULL REFERENCES winscripts(id) ON DELETE CASCADE,
    version     INT  NOT NULL,
    content     TEXT NOT NULL DEFAULT '',
    author_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    author      TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (script_id, version)
);

CREATE INDEX IF NOT EXISTS idx_winscript_versions_s ON winscript_versions(script_id, version DESC);

-- One execution of a script against a target (a single Windows host, several hosts,
-- or a Fleet group). output holds the combined per-host captured log.
CREATE TABLE IF NOT EXISTS winscript_runs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    script_id      UUID NOT NULL REFERENCES winscripts(id) ON DELETE CASCADE,
    script_version INT  NOT NULL DEFAULT 0,
    requested_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    requester      TEXT NOT NULL DEFAULT '',
    target_kind    TEXT NOT NULL DEFAULT 'host', -- host|group
    target_id      UUID,                          -- host id or group id
    target_name    TEXT NOT NULL DEFAULT '',
    host_count     INT  NOT NULL DEFAULT 0,
    status         TEXT NOT NULL DEFAULT 'pending', -- pending|running|completed|failed
    exit_code      INT,
    output         TEXT NOT NULL DEFAULT '',
    error          TEXT NOT NULL DEFAULT '',
    scheduled      BOOLEAN NOT NULL DEFAULT false,
    instance_id    UUID, -- HA: which backend instance owns the in-flight run
    started_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_winscript_runs_s ON winscript_runs(script_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_winscript_runs_status ON winscript_runs(status);
