-- Vulnerability scanning. Distinct from the OpenSCAP compliance scans (host_scans,
-- which evaluate hardening rules): these match a host's installed packages against
-- a CVE database (Anchore Grype, run in the grype-scanner sidecar) and record each
-- CVE with its CVSS score. One vuln_scans row per host scan; one vuln_findings row
-- per CVE-on-package.

CREATE TABLE IF NOT EXISTS vuln_scans (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id      UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    requester    TEXT NOT NULL DEFAULT '',
    scheduled    BOOLEAN NOT NULL DEFAULT false,
    status       TEXT NOT NULL DEFAULT 'pending', -- pending|running|completed|failed
    error        TEXT NOT NULL DEFAULT '',
    db_built_at  TIMESTAMPTZ,                      -- build date of the CVE DB used
    total        INT NOT NULL DEFAULT 0,
    critical     INT NOT NULL DEFAULT 0,
    high         INT NOT NULL DEFAULT 0,
    medium       INT NOT NULL DEFAULT 0,
    low          INT NOT NULL DEFAULT 0,
    negligible   INT NOT NULL DEFAULT 0,
    unknown      INT NOT NULL DEFAULT 0,
    max_cvss     DOUBLE PRECISION NOT NULL DEFAULT 0,
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_vuln_scans_host ON vuln_scans(host_id, created_at DESC);

CREATE TABLE IF NOT EXISTS vuln_findings (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id           UUID NOT NULL REFERENCES vuln_scans(id) ON DELETE CASCADE,
    cve               TEXT NOT NULL,
    package           TEXT NOT NULL DEFAULT '',
    installed_version TEXT NOT NULL DEFAULT '',
    fixed_version     TEXT NOT NULL DEFAULT '',
    severity          TEXT NOT NULL DEFAULT '',
    cvss_score        DOUBLE PRECISION NOT NULL DEFAULT 0,
    cvss_vector       TEXT NOT NULL DEFAULT '',
    data_source       TEXT NOT NULL DEFAULT '',
    description       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_vuln_findings_scan ON vuln_findings(scan_id, cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_vuln_findings_cve ON vuln_findings(cve);
