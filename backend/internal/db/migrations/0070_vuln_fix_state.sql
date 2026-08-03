-- Record the scanner's fix STATE per finding, and count scan summaries by distinct
-- CVE rather than by CVE-on-package.
--
-- Why: an empty fixed_version conflated two very different situations. Grype (via
-- the distro security trackers) distinguishes:
--
--   fixed      a fixed version exists — you are behind, this is actionable
--   not-fixed  the distro acknowledges it and has not shipped a fix yet
--   wont-fix   the distro assessed it and decided not to fix it (Debian "no-DSA",
--              minor issue) — it will never become actionable via an upgrade
--   unknown    no fix data
--
-- On a pristine, fully-patched debian:12 the split is ~59% not-fixed / ~41%
-- wont-fix and 0% fixed. Collapsing all of that into "fixed_version = ''" made the
-- roll-up's Fixable column read "—" on every host, hiding the actually useful fact
-- (nothing outstanding) behind a four-figure total.
--
-- The summary counts (total/critical/.../fixable) now count each CVE ONCE rather
-- than once per affected binary package. One source package fans out across many
-- binaries (glibc -> libc6, libc-bin, ...), which inflated totals ~2.1x on the same
-- sample: 154 findings for 72 distinct CVEs. vuln_findings still holds one row per
-- CVE-on-package, so the drill-down keeps full remediation detail.
--
-- Existing rows keep their old (inflated, state-less) numbers until re-scanned;
-- fix_state '' reads as "unknown" and falls back to the fixed_version check.

ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS fix_state TEXT NOT NULL DEFAULT '';

-- Distinct CVEs whose fix state is wont-fix everywhere they appear: acknowledged,
-- assessed, and never going to be fixed by an upgrade. Surfaced separately so it can
-- be subtracted from the headline number instead of padding it.
ALTER TABLE vuln_scans ADD COLUMN IF NOT EXISTS wont_fix INT NOT NULL DEFAULT 0;
