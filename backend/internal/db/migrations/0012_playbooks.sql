-- Ansible playbook management: author/edit playbooks in the UI, validate/lint
-- them, and (later) run them against hosts/groups through the Fleet SSH path.
--
-- Two permissions, both Administrator-only by default:
--   Playbook.Edit  -- author, upload, edit, delete playbooks; validate/lint.
--   Playbook.Run   -- execute a playbook against hosts (arbitrary root-level
--                     change across the fleet); granted separately on purpose.

INSERT INTO permissions(key, description) VALUES
    ('Playbook.Edit', 'Author, edit, and validate Ansible playbooks'),
    ('Playbook.Run',  'Run Ansible playbooks against hosts (executes changes on hosts)')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, p.key
FROM roles r
CROSS JOIN (VALUES ('Playbook.Edit'), ('Playbook.Run')) AS p(key)
WHERE r.name = 'Administrator'
ON CONFLICT DO NOTHING;

-- A playbook: a single YAML document plus metadata. `version` is bumped on each
-- content change; the prior content is snapshotted into playbook_versions.
CREATE TABLE IF NOT EXISTS playbooks (
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

CREATE INDEX IF NOT EXISTS idx_playbooks_name ON playbooks(lower(name));

-- Immutable history: one row per saved revision so edits are auditable and
-- recoverable.
CREATE TABLE IF NOT EXISTS playbook_versions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    version     INT  NOT NULL,
    content     TEXT NOT NULL DEFAULT '',
    author_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    author      TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (playbook_id, version)
);

CREATE INDEX IF NOT EXISTS idx_playbook_versions_pb ON playbook_versions(playbook_id, version DESC);

-- One execution of a playbook against a target (a single host or a Fleet group).
-- The actual SSH/run wiring lands in Phase 2; the table is created now so the
-- model and startup reconciler are in place. output holds the captured log.
CREATE TABLE IF NOT EXISTS playbook_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id     UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    playbook_version INT NOT NULL DEFAULT 0,
    requested_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    requester       TEXT NOT NULL DEFAULT '',
    target_kind     TEXT NOT NULL DEFAULT 'host', -- host|group
    target_id       UUID,                          -- host id or group id
    target_name     TEXT NOT NULL DEFAULT '',
    host_count      INT  NOT NULL DEFAULT 0,
    check_mode      BOOLEAN NOT NULL DEFAULT false, -- ansible --check (dry run)
    status          TEXT NOT NULL DEFAULT 'pending', -- pending|running|completed|failed
    exit_code       INT,
    output          TEXT NOT NULL DEFAULT '',
    error           TEXT NOT NULL DEFAULT '',
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_playbook_runs_pb ON playbook_runs(playbook_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_playbook_runs_status ON playbook_runs(status);
