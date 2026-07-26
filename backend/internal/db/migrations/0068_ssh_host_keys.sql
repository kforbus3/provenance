-- Persisted SSH host-key pins for the gateway's trust-on-first-use verifier.
--
-- Previously pins lived only in process memory, so after a backend restart the first
-- connection to any host was re-pinned blindly — a MITM during that window (or a silent
-- host rebuild) would be accepted as the new pin. Persisting the pins makes them survive
-- restarts, so a mismatch is detected for the life of the host, not just the process.
--
-- `source` distinguishes a key learned by TOFU ('tofu') from one an operator pinned
-- deliberately ('pinned', e.g. pre-seeded at enrollment) so the first connect can be
-- verified rather than trusted. This is infrastructure state shared across tenants, so
-- the table is intentionally NOT tenant-scoped / RLS-forced.
CREATE TABLE IF NOT EXISTS ssh_host_keys (
    host        TEXT PRIMARY KEY,          -- knownhosts-normalized "host" or "[host]:port"
    key_line    TEXT NOT NULL,             -- "<type> <base64>\n" (authorized-key line)
    key_type    TEXT NOT NULL DEFAULT '',  -- e.g. ssh-ed25519 (display/audit)
    source      TEXT NOT NULL DEFAULT 'tofu', -- tofu | pinned
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
