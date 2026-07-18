-- Credential vault: store static credentials (passwords, SSH keys, API keys) that
-- systems unable to use Fleet's ephemeral certificates need. Secret material is
-- encrypted at rest with secretbox (a dedicated FLEET_VAULT_PASSPHRASE) and lives
-- only in the versions table; the vault_secrets row holds metadata only. Access is
-- Credential.Manage for full control, plus per-secret grants that delegate reveal
-- (view) / injection (use) / edit (manage) to specific users or groups.

CREATE TABLE IF NOT EXISTS vault_secrets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    folder      TEXT NOT NULL DEFAULT '',           -- organizational label
    type        TEXT NOT NULL DEFAULT 'password',    -- password | ssh_key | api_key | generic
    username    TEXT NOT NULL DEFAULT '',            -- the account the secret is for
    target      TEXT NOT NULL DEFAULT '',            -- host/URL the secret is used against
    description TEXT NOT NULL DEFAULT '',
    version     INT NOT NULL DEFAULT 1,              -- current version number
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_vault_secrets_folder ON vault_secrets(folder, name);

-- Encrypted secret material, one row per version (rotation history + rollback).
CREATE TABLE IF NOT EXISTS vault_secret_versions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id  UUID NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    version    INT NOT NULL,
    sealed     TEXT NOT NULL,                        -- secretbox-sealed payload (never plaintext)
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (secret_id, version)
);

-- Per-secret access grants to a user or group.
CREATE TABLE IF NOT EXISTS vault_grants (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id    UUID NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    subject_kind TEXT NOT NULL,                      -- user | group
    subject_id   UUID NOT NULL,
    access       TEXT NOT NULL DEFAULT 'view',       -- view | use | manage
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (secret_id, subject_kind, subject_id)
);
CREATE INDEX IF NOT EXISTS idx_vault_grants_subject ON vault_grants(subject_kind, subject_id);

INSERT INTO permissions(key, description) VALUES
    ('Credential.Manage', 'Create, edit, delete, and grant access to vault credentials'),
    ('Credential.View',   'Reveal the plaintext of a vault credential'),
    ('Credential.Use',    'Use a vault credential to authenticate a session (injection)'),
    ('Credential.Rotate', 'Rotate vault credentials')
ON CONFLICT (key) DO NOTHING;

-- Full vault management to administrators; reveal/use also to operators. Auditors
-- are deliberately NOT given reveal (they review, they don't extract secrets).
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Credential.Manage' FROM roles r WHERE r.name IN ('Super Administrator', 'Administrator')
ON CONFLICT DO NOTHING;
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, p.key FROM roles r CROSS JOIN (VALUES ('Credential.View'),('Credential.Use'),('Credential.Rotate')) AS p(key)
WHERE r.name IN ('Super Administrator', 'Administrator', 'Operator')
ON CONFLICT DO NOTHING;
