-- Keep the package inventory a scan collected, as a downloadable CycloneDX SBOM.
--
-- Why: the vulnerability scanner already pulls every managed host's package
-- database over SSH, hands it to grype, and stores only the findings. The
-- inventory itself — the full list of what is installed, with exact versions —
-- was discarded, even though it is the artifact people actually ask for.
--
-- "Give us a software bill of materials for this system" is a compliance
-- question (CMMC, FedRAMP, EO 14028 / SSDF), and answering it should not require
-- a second tool, a rebuild, or an agent. Everything needed is already collected
-- on the existing schedule.
--
-- Stored in its own table rather than as a column on vuln_scans:
--
--   * a 400-package host produces ~60 KB of JSON, and ListVulnScans selects
--     every column — putting it inline would drag that payload through the
--     scan list, the roll-up and the assistant's history queries;
--   * it can be pruned on a different retention schedule from the findings,
--     which are small and worth keeping far longer.
--
-- Windows hosts already build a CycloneDX SBOM in memory to feed grype's
-- /scan-sbom endpoint; that one is now persisted here too, so both platforms
-- answer the same question the same way.

CREATE TABLE IF NOT EXISTS vuln_sboms (
    scan_id      UUID PRIMARY KEY REFERENCES vuln_scans(id) ON DELETE CASCADE,
    host_id      UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    -- "deb", "rpm" or "windows": which inventory source produced the components.
    -- Kept so a consumer can tell a purl-based Linux BOM from the CPE-based
    -- Windows one without parsing the document.
    pkg_format   TEXT NOT NULL DEFAULT '',
    os_id        TEXT NOT NULL DEFAULT '',
    os_version   TEXT NOT NULL DEFAULT '',
    components   INT  NOT NULL DEFAULT 0,
    sbom         JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The common query is "latest SBOM for this host", which is a host-scoped
-- lookup ordered by time, not a scan-id lookup.
CREATE INDEX IF NOT EXISTS idx_vuln_sboms_host ON vuln_sboms(host_id, created_at DESC);
