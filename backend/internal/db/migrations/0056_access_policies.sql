-- Attribute-based access control (ABAC) / policy-as-code: contextual rules that can
-- DENY a host connection that RBAC would otherwise allow, based on host attributes
-- (environment/tags/protocol), time-of-day windows, and role exemptions. Policies only
-- restrict — they never grant access beyond RBAC — and super administrators are always
-- exempt (no self-lockout). Evaluated at connect time for interactive sessions and the
-- ad-hoc command runner.
CREATE TABLE IF NOT EXISTS access_policies (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    enabled       BOOLEAN NOT NULL DEFAULT true,
    priority      INT NOT NULL DEFAULT 100,            -- lower evaluated first; first matching deny wins
    effect        TEXT NOT NULL DEFAULT 'deny' CHECK (effect IN ('deny')),
    -- Host matchers (empty array = matches any):
    environments  TEXT[] NOT NULL DEFAULT '{}',        -- host.environment in this set
    tags          TEXT[] NOT NULL DEFAULT '{}',        -- host has ANY of these tags
    protocols     TEXT[] NOT NULL DEFAULT '{}',        -- host.protocol in this set (ssh/rdp)
    -- Subject exemption: users holding ANY of these role names are not subject to the rule.
    exempt_roles  TEXT[] NOT NULL DEFAULT '{}',
    -- Time window (evaluated in the configured display timezone). active_days empty = all
    -- days (0=Sunday..6=Saturday). If active_start_min = active_end_min the time condition
    -- is ignored (rule always time-active); start > end wraps past midnight.
    active_days       INT[] NOT NULL DEFAULT '{}',
    active_start_min  INT NOT NULL DEFAULT 0,
    active_end_min    INT NOT NULL DEFAULT 0,
    deny_message  TEXT NOT NULL DEFAULT '',
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_access_policies_enabled ON access_policies(enabled, priority);

INSERT INTO permissions(key, description) VALUES
    ('AccessPolicy.Manage', 'Create, edit, and delete attribute-based access-control policies')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'AccessPolicy.Manage' FROM roles r WHERE r.name IN ('Super Administrator', 'Administrator')
ON CONFLICT DO NOTHING;
