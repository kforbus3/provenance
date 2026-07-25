-- Generic per-host options as JSONB (mirrors the rdp_options precedent), so
-- device-specific attributes can grow without a schema change per addition. The
-- first use is marking a host as a RouterOS API device:
--   {"routerOsApi": true, "apiPort": 8728}
-- which makes a playbook run open an API tunnel through the jump host and drive it
-- via community.routeros.api. Empty object = a plain host (pre-existing behaviour).
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS host_options JSONB NOT NULL DEFAULT '{}'::jsonb;
