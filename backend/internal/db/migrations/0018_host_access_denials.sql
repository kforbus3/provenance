-- Per-user, per-host access denial. Overrides EVERY access source (direct grant,
-- group membership, active temporary grant), so an admin can remove one user's
-- access to one host without restructuring groups. Removing the row restores
-- whatever access the user would otherwise have.
CREATE TABLE IF NOT EXISTS host_access_denials (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    host_id    UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, host_id)
);
CREATE INDEX IF NOT EXISTS idx_host_denials_user ON host_access_denials(user_id);
