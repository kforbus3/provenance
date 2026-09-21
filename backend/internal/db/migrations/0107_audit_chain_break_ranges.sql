-- Acknowledging one historical event that broke thousands of rows, rather than
-- thousands of separate findings.
--
-- audit_chain_breaks (0105) records an investigated break one sequence at a time,
-- which is the right shape for what it was built for: a break is rare, and each one
-- deserves its own account of what was found.
--
-- It is the wrong shape for the damage the foreign key dropped in 0106 actually did.
-- That constraint was ON DELETE SET NULL on audit_events.actor_id, so deleting a user
-- silently nulled a column the hash covers on every event they had ever caused. The
-- first production chain examined after the fix had 3,054 broken rows out of 5,521 --
-- 55% of the log -- from a handful of accounts being deleted over three months. Every
-- deployment that ever deleted a user has some version of this.
--
-- Acknowledging that one row at a time is not an option. It is 3,054 attestations
-- about a single event, and because each acknowledgement is itself written as a
-- chained audit event, the log would grow by 3,054 rows while being investigated --
-- more new rows than the chain had before. The verdict would stay BROKEN throughout,
-- which is the state that teaches people to stop looking at it.
--
-- So a range can be acknowledged. The safeguards are what make that acceptable:
--
--   * covered_count pins how many breaks were in the range when it was investigated.
--     If the number of covered breaks inside the range ever EXCEEDS it, the whole
--     acknowledgement stops being honoured and every break under it is reported
--     again. An acknowledgement cannot silently absorb a break that arrives later.
--
--   * Only breaks whose actor_id is NULL and whose prev_hash still links to the
--     previous row are ever covered. A row with an intact actor id did not lose one,
--     and a broken LINK means rows were removed, inserted or reordered -- neither has
--     the signature of this defect, so neither is coverable in bulk and both keep
--     being reported individually.
--
--   * evidence_seq works exactly as in 0105: the acknowledgement is honoured only
--     while the chained audit event recording it is present and itself verifies,
--     which needs the HMAC key. An entry inserted straight into the database
--     accounts for nothing.
--
-- Nothing here repairs anything. The rows stay exactly as they are, the breaks are
-- reported for ever, and the range is reported beside the verdict with its count and
-- its note. What it changes is only whether they are NEWS -- and, crucially, whether
-- a genuine break arriving tomorrow is visible behind them.
CREATE TABLE IF NOT EXISTS audit_chain_break_ranges (
    id                BIGSERIAL PRIMARY KEY,
    from_seq          BIGINT NOT NULL,
    to_seq            BIGINT NOT NULL,
    covered_count     INTEGER NOT NULL,
    evidence_seq      BIGINT NOT NULL,
    acknowledged_by   UUID,
    acknowledged_name TEXT NOT NULL DEFAULT '',
    note              TEXT NOT NULL DEFAULT '',
    acknowledged_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT audit_chain_break_ranges_ordered CHECK (to_seq >= from_seq),
    CONSTRAINT audit_chain_break_ranges_counted CHECK (covered_count > 0)
);

CREATE INDEX IF NOT EXISTS audit_chain_break_ranges_from_to_idx
    ON audit_chain_break_ranges (from_seq, to_seq);
