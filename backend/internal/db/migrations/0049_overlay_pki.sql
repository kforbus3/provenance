-- Overlay PKI: an X.509 certificate authority (ECDSA P-256) for the FIPS OpenVPN /
-- strongSwan overlay. This is DISTINCT from the SSH CA (ca_keys): OpenVPN
-- authenticates peers with X.509 certificates, which an SSH CA cannot issue. These
-- tables are only touched when FLEET_OVERLAY=openvpn (FIPS mode) — the default
-- WireGuard overlay never uses them, so a non-FIPS install is unaffected.
CREATE TABLE IF NOT EXISTS overlay_ca (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_pem    TEXT NOT NULL,          -- X.509 CA certificate (PEM)
    key_enc     BYTEA NOT NULL,         -- ECDSA private key, secretbox-sealed at rest
    fingerprint TEXT NOT NULL,          -- SHA-256 of the DER cert, for display
    active      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at  TIMESTAMPTZ
);

-- Issued overlay client certificates (one per enrolled host on the OpenVPN overlay),
-- tracked for status and future revocation (CRL) support.
CREATE TABLE IF NOT EXISTS overlay_clients (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id     UUID REFERENCES hosts(id) ON DELETE CASCADE,
    common_name TEXT NOT NULL,
    serial      TEXT NOT NULL,          -- decimal serial of the issued cert
    not_after   TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_overlay_clients_host ON overlay_clients(host_id);
