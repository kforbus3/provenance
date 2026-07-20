-- Per-host overlay transport selection. Empty = use the deployment default
-- (FLEET_OVERLAY, itself derived from FIPS mode). This lets an operator choose
-- wireguard | openvpn | strongswan per host at enrollment time. Only the enrollment
-- path reads it, and existing rows default to '' (deployment default), so this is a
-- no-op for current hosts.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS overlay TEXT NOT NULL DEFAULT '';
