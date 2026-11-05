-- The other IDs a vulnerability finding is known by.
--
-- grype keys a finding on whichever advisory matched it. For a distro package
-- that is the CVE; for a Go module, npm or PyPI package it is usually the GitHub
-- advisory (GHSA-xxxx-xxxx-xxxx), and the CVE appears only among the match's
-- relatedVulnerabilities -- which the scanner used to drop. "Which hosts have
-- CVE-2024-24790" then missed every Go binary carrying it and answered "none",
-- which reads exactly like a clean bill of health. Aliases are filled in from the
-- next scan of each host; findings recorded before then have none.
ALTER TABLE vuln_findings
    ADD COLUMN IF NOT EXISTS aliases TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_vuln_findings_aliases ON vuln_findings USING gin (aliases);
