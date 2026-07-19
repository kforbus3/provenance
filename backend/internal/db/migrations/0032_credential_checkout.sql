-- Credential check-out: high-value credentials can require a time-boxed check-out
-- before they may be revealed or injected, optionally gated by a second person's
-- approval (the classic PAM workflow). A secret's access_policy controls this:
--   open     — reveal/inject per grants directly (default; current behaviour)
--   checkout — must check the credential out first (self-service, time-boxed, tracked)
--   approval — must request a check-out; a Credential.Approve holder (not the
--              requester) approves before access becomes active.

ALTER TABLE vault_secrets
    ADD COLUMN IF NOT EXISTS access_policy TEXT NOT NULL DEFAULT 'open'; -- open | checkout | approval

CREATE TABLE IF NOT EXISTS vault_checkouts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id     UUID NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- the requester
    reason        TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'active', -- pending | active | denied | expired | checked_in
    requested_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    decided_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    decided_at    TIMESTAMPTZ,
    checked_in_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_vault_checkouts_user ON vault_checkouts(user_id, status);
CREATE INDEX IF NOT EXISTS idx_vault_checkouts_active ON vault_checkouts(secret_id, user_id, status);
CREATE INDEX IF NOT EXISTS idx_vault_checkouts_status ON vault_checkouts(status);

-- Who may approve a credential check-out. Kept distinct from Credential.Manage so
-- approving privileged access can be a separate, auditable role decision.
INSERT INTO permissions(key, description) VALUES
    ('Credential.Approve', 'Approve or deny credential check-out requests')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Credential.Approve' FROM roles r WHERE r.name IN ('Super Administrator', 'Administrator')
ON CONFLICT DO NOTHING;
