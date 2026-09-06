-- Make the vulnerability roll-up lead with what is actionable, and record which
-- SOURCE package a finding really belongs to.
--
-- Two problems this fixes, both observed on a fully-patched fleet:
--
-- 1. The roll-up's most prominent columns (Critical/High/Medium) counted every CVE
--    regardless of fix state, so a host with nothing outstanding still rendered a
--    wall of red while the one number that mattered — fixable = 0 — sat in a small
--    chip further right. Severity counts scoped to the FIXABLE subset let the table
--    lead with "what can I patch right now" and demote the rest.
--
-- 2. max_cvss is 10.0 on essentially every Linux host: it is the worst NVD score of
--    any CVE touching any installed package, so it discriminates nothing and sorts
--    nothing. fixable_max_cvss answers the question the column was meant to ask —
--    how bad is the worst thing I can actually fix — and is 0 when nothing is.
--
-- source_package records the upstream/source package grype matched on. Distro CVE
-- trackers key on the SOURCE package, so one source fans out across every binary it
-- builds: on a sample host libcpupower1 and linux-cpupower (both built from the
-- `linux` source) carried 227 of 547 critical+high CVEs — 41% of the alarming number
-- was the Linux kernel's CVE list attributed to a CPU-frequency helper. Storing the
-- source lets the drill-down group those into one `linux` row and label them as the
-- kernel CVEs they are, instead of repeating them per binary against a package that
-- is not what is vulnerable.
--
-- Existing rows keep their defaults until re-scanned: fixable_* read as 0 (which is
-- also what a fully-patched host reports, so the roll-up stays honest) and
-- source_package reads as empty, which the UI falls back to the binary name for.

ALTER TABLE vuln_scans
    ADD COLUMN IF NOT EXISTS fixable_critical INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS fixable_high     INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS fixable_medium   INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS fixable_max_cvss DOUBLE PRECISION NOT NULL DEFAULT 0;

ALTER TABLE vuln_findings
    ADD COLUMN IF NOT EXISTS source_package TEXT NOT NULL DEFAULT '';
