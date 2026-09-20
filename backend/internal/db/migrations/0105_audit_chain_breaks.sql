-- Acknowledging a break in the audit chain, without repairing it.
--
-- A detected break is permanent: the whole point of the chain is that altered or
-- missing rows cannot be made to verify again, and anything that "repaired" one would
-- be the forgery the design exists to prevent. But leaving the verdict at BROKEN for
-- ever has its own cost — the indicator never returns to green, so it stops being read,
-- and a second, real break arrives at a screen everybody has learned to ignore.
--
-- So a break can be ACKNOWLEDGED: someone with the permission records that they
-- investigated it, when, and what they found. Nothing in audit_events is touched. The
-- altered or missing data stays exactly as it is, and verification reports the break
-- for ever — but as reviewed, and it carries on checking the rows after it, so a NEW
-- break is still visible.
--
-- evidence_seq is what stops this becoming a hole. An acknowledgement is only honoured
-- when the audit event that recorded it is present and itself verifies as part of the
-- chain. A party with database write access can insert a row here, but they cannot
-- produce the chained event it points at without the HMAC key — so an unsupported
-- acknowledgement is ignored and the break is reported as if it were never made.
CREATE TABLE IF NOT EXISTS audit_chain_breaks (
    broken_at_seq    BIGINT PRIMARY KEY,
    evidence_seq     BIGINT NOT NULL,
    acknowledged_by  UUID,
    acknowledged_name TEXT NOT NULL DEFAULT '',
    note             TEXT NOT NULL DEFAULT '',
    acknowledged_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
