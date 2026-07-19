-- Track the "fixable" subset of a vulnerability scan: findings that have an
-- available fix version. This lets the UI distinguish "present" from "actionable
-- right now" (a fix exists but isn't applied) — the equivalent of the Windows
-- missing-updates view — without loading every finding for the roll-up. Existing
-- scans default to 0 until re-scanned.

ALTER TABLE vuln_scans ADD COLUMN IF NOT EXISTS fixable INT NOT NULL DEFAULT 0;
