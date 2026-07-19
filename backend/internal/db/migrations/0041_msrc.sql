-- MSRC (Microsoft Security Response Center) KB→CVE mapping, used to give Windows
-- vulnerability scans real CVE IDs, severity, and CVSS scores. The Windows Update
-- Agent reports which KBs a host is missing, but not (reliably) the CVEs/severity
-- they remediate; that authoritative data lives in Microsoft's Security Update
-- Guide (CVRF documents), keyed by KB. This table caches the flattened mapping,
-- populated either online (fetch from api.msrc.microsoft.com) or via offline import.

CREATE TABLE IF NOT EXISTS msrc_updates (
    kb          TEXT NOT NULL,              -- KB article number, digits only (e.g. "5099536")
    cve         TEXT NOT NULL,              -- e.g. "CVE-2026-1234"
    severity    TEXT NOT NULL DEFAULT '',   -- MSRC severity: Critical|Important|Moderate|Low
    cvss        DOUBLE PRECISION NOT NULL DEFAULT 0,
    vector      TEXT NOT NULL DEFAULT '',   -- CVSS vector string
    title       TEXT NOT NULL DEFAULT '',
    release     TEXT NOT NULL DEFAULT '',   -- MSRC release id, e.g. "2026-Jul"
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (kb, cve)
);

CREATE INDEX IF NOT EXISTS idx_msrc_updates_kb ON msrc_updates(kb);
