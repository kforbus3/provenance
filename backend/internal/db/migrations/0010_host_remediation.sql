-- OpenSCAP remediation: apply fixes for selected failed rules from a scan.
-- Write-capable and dangerous (it changes host config), so it has its own
-- permission, granted to Administrator only by default.

INSERT INTO permissions(key, description) VALUES
    ('Host.Remediate', 'Apply OpenSCAP remediations to hosts (modifies host configuration)')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Host.Remediate' FROM roles r WHERE r.name = 'Administrator'
ON CONFLICT DO NOTHING;

-- Keep each scan's results XML so failed rules can be listed and fixes generated.
ALTER TABLE host_scans ADD COLUMN IF NOT EXISTS results_path TEXT NOT NULL DEFAULT '';

-- One remediation run: the rules a user chose to fix on a host, the outcome, and
-- a link to the verification re-scan.
CREATE TABLE IF NOT EXISTS host_remediations (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id      UUID NOT NULL REFERENCES host_scans(id) ON DELETE CASCADE,
    host_id      UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    requester    TEXT NOT NULL DEFAULT '',
    rule_ids     TEXT[] NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'pending', -- pending|running|completed|failed
    exit_code    INT,
    output       TEXT NOT NULL DEFAULT '',
    rescan_id    UUID REFERENCES host_scans(id) ON DELETE SET NULL,
    error        TEXT NOT NULL DEFAULT '',
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_host_remediations_scan ON host_remediations(scan_id, created_at DESC);
