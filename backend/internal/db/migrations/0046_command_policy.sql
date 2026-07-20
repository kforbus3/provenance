-- Command control: a privileged/dangerous-command policy evaluated at the terminal
-- relay. Each rule matches typed command lines (RE2 regex) and applies an action:
--   flag     — allow the command, but audit + alert (advisory oversight)
--   block    — refuse to run the command at the relay
--   approval — refuse until an approver grants a time-boxed waiver, then allow re-run
-- Rules are global or scoped to a host group. NOTE: relay enforcement inspects the
-- interactive input stream, so it is a strong deterrent + full audit trail, not a
-- cryptographic guarantee (a determined insider can obfuscate); documented as such.
CREATE TABLE IF NOT EXISTS command_policies (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name           TEXT NOT NULL,
    pattern        TEXT NOT NULL,                 -- RE2 regex matched against the command line
    action         TEXT NOT NULL CHECK (action IN ('flag','block','approval')),
    scope_kind     TEXT NOT NULL DEFAULT 'global' CHECK (scope_kind IN ('global','group')),
    scope_group_id UUID REFERENCES groups(id) ON DELETE CASCADE, -- required when scope_kind='group'
    enabled        BOOLEAN NOT NULL DEFAULT true,
    created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_command_policies_enabled ON command_policies(enabled);

-- Approval requests + granted waivers for 'approval' rules. A request row is
-- created when a user hits an approval rule; an approver grants it, producing a
-- time-boxed waiver that lets that user re-run matching commands on that host until
-- it expires.
CREATE TABLE IF NOT EXISTS command_approvals (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id    UUID REFERENCES command_policies(id) ON DELETE SET NULL,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username     TEXT NOT NULL DEFAULT '',
    host_id      UUID REFERENCES hosts(id) ON DELETE CASCADE,
    hostname     TEXT NOT NULL DEFAULT '',
    command      TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied')),
    approved_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at   TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ                     -- waiver validity window when approved
);
CREATE INDEX IF NOT EXISTS idx_command_approvals_active ON command_approvals(user_id, host_id, status);

INSERT INTO permissions(key, description) VALUES
    ('CommandPolicy.Manage', 'Manage command-control policy and approve gated commands')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'CommandPolicy.Manage' FROM roles r WHERE r.name IN ('Super Administrator', 'Administrator')
ON CONFLICT DO NOTHING;
