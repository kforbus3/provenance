-- Overlay certificate revocation, for the OpenVPN CRL.
--
-- Separate from overlay_clients on purpose. overlay_clients.host_id is
-- ON DELETE CASCADE, so a host's issued-cert rows vanish the moment the host is
-- deleted — which is exactly when its certificate most needs to stay revoked. A
-- revocation list is a list of serials; coupling it to host lifetime means the
-- entries disappear precisely when they start to matter. This mirrors
-- cert_revocations (0001_init.sql), which does the same job for the SSH CA and is
-- likewise keyed only by serial.
--
-- not_after lets an expired entry be pruned: a certificate past its own validity is
-- refused by the server anyway, so keeping it only grows the CRL.
CREATE TABLE IF NOT EXISTS overlay_revocations (
    serial      TEXT PRIMARY KEY,       -- decimal serial, matching overlay_clients.serial
    common_name TEXT NOT NULL DEFAULT '',
    not_after   TIMESTAMPTZ NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_overlay_revocations_not_after ON overlay_revocations(not_after);
