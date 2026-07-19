-- Per-host RDP display/security and clipboard settings, applied when brokering the
-- session to guacd. Stored as JSONB so the option set can grow (e.g. drive
-- redirection in a later phase) without a schema change. Empty object = guacd
-- defaults, which is the pre-existing behaviour.
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS rdp_options JSONB NOT NULL DEFAULT '{}'::jsonb;
