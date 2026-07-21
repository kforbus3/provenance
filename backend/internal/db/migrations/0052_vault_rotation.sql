-- Scheduled rotation policy for vaulted password credentials. A background loop
-- rotates a credential on its host every rotation_interval_days, reusing the same
-- change-and-verify path as the on-demand rotate endpoint. rotation_interval_days = 0
-- (the default) means no automatic rotation.
ALTER TABLE vault_secrets
    ADD COLUMN IF NOT EXISTS rotation_interval_days INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_rotated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS next_rotation_at TIMESTAMPTZ;

-- Partial index: the rotation loop only scans credentials that have a policy set.
CREATE INDEX IF NOT EXISTS idx_vault_secrets_next_rotation
    ON vault_secrets (next_rotation_at)
    WHERE rotation_interval_days > 0;
