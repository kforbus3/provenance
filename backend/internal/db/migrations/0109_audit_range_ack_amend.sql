-- Let a range acknowledgement's note be corrected.
--
-- The note is the whole value of an acknowledgement: it is what a compliance reader
-- sees in an evidence pack, and the API refuses an empty one for that reason. But it
-- was write-once. AcknowledgeAuditChainRange was a plain INSERT with nothing unique
-- about (from_seq, to_seq), so acknowledging the same span again added a SECOND row
-- that the verifier then ignored -- the first matching range takes the covered breaks,
-- and a range covering none is skipped. The correction appeared to be accepted and
-- changed nothing.
--
-- That is a bad way for this field to behave. The first note somebody writes is often
-- the weakest: written at the moment of discovery, before the cause is fully
-- established, and sometimes recording who suggested the acknowledgement rather than
-- what the investigation found. A record that cannot be improved gets worse over time,
-- because the understanding moves on and the text does not.
--
-- Amending does not erase anything. Each acknowledgement is backed by a chained audit
-- event, and an amendment writes a NEW one, so the audit log carries every version of
-- the note in order while the honoured record points at the latest. The history of what
-- was believed, and when, stays in the one place that cannot be rewritten.
--
-- Deduplicate before adding the constraint: any deployment that tried to correct a note
-- already has the extra rows this could not have created. Keep the newest, which is the
-- one whose text somebody last intended.
DELETE FROM audit_chain_break_ranges a
USING audit_chain_break_ranges b
WHERE a.from_seq = b.from_seq
  AND a.to_seq = b.to_seq
  AND (a.acknowledged_at, a.id) < (b.acknowledged_at, b.id);

CREATE UNIQUE INDEX IF NOT EXISTS audit_chain_break_ranges_span_uniq
    ON audit_chain_break_ranges (from_seq, to_seq);
