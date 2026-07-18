-- Service accounts + API tokens.
--
-- A service account is a non-human identity that authenticates via API tokens
-- (for CI/CD, IaC, monitoring). It is modeled as a users row flagged
-- is_service_account: it carries roles and group-based host access exactly like a
-- human user, but has no password/credential row and cannot log in interactively
-- or via SSO. This reuses the existing Principal, RBAC, and host-access machinery
-- unchanged — the token authenticates as the service account's user id.

ALTER TABLE users ADD COLUMN IF NOT EXISTS is_service_account BOOLEAN NOT NULL DEFAULT false;

-- API tokens are hashed bearer credentials. The plaintext (prefixed "flt_") is
-- shown once at creation; only its SHA-256 hash is stored. One service account may
-- hold several tokens so they can be rotated without changing its identity/grants.
CREATE TABLE IF NOT EXISTS api_tokens (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_account_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    token_hash         TEXT NOT NULL UNIQUE,
    prefix             TEXT NOT NULL DEFAULT '',   -- non-secret display hint, e.g. "flt_a1b2c3d4"
    created_by         UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ,                -- NULL = no expiry
    last_used_at       TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_sa ON api_tokens(service_account_id, created_at DESC);

-- Permission gating service-account and token management.
INSERT INTO permissions(key, description) VALUES
    ('ServiceAccount.Manage', 'Create and manage service accounts and their API tokens')
ON CONFLICT (key) DO NOTHING;

-- Grant to the built-in admin roles. Super Administrator already passes every
-- check via Admin.All, but grant explicitly for clarity; Administrator needs it.
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'ServiceAccount.Manage' FROM roles r
WHERE r.name IN ('Super Administrator', 'Administrator')
ON CONFLICT DO NOTHING;
