-- Retention may shorten the chain without making it look tampered with.
--
-- Verification walks from prev="" and compares each row's prev_hash to the previous
-- row's hash. After PruneAuditEventsBefore removes the oldest rows, the first RETAINED
-- row still points at a hash that is no longer present -- so the chain reports a break
-- at that row, and an UNLINKED one, which is the signature of rows being removed.
--
-- It is the signature because rows were removed. But there is a difference between a
-- deletion somebody declared as policy and a deletion somebody performed quietly, and
-- verification could not tell them apart: PruneAuditEventsBefore's own comment claimed
-- "the rows that remain still verify forward from the new oldest entry", and a test
-- shows they do not. Anyone who enabled PROV_AUDIT_RETENTION got a chain that reported
-- itself broken for ever, and the only way to clear old damaged history was to create a
-- fresh, permanent break.
--
-- So a prune declares its boundary. The row records the last sequence removed and the
-- prev_hash the new first row carries, and verification seeds its walk from that hash
-- instead of "" -- but only when the boundary is backed by a chained audit event that
-- itself verifies, exactly as an acknowledgement is (0105, 0107). The event is written
-- AFTER the delete, so it survives into the retained chain, and forging one needs
-- PROV_AUDIT_HMAC_KEY.
--
-- An undeclared deletion therefore still breaks the chain, loudly, with no way to
-- silence it from the database alone.
CREATE TABLE IF NOT EXISTS audit_chain_prunes (
    id                BIGSERIAL PRIMARY KEY,
    -- The highest seq removed, and the hash the first surviving row chains to.
    through_seq       BIGINT NOT NULL,
    boundary_hash     TEXT   NOT NULL,
    rows_removed      BIGINT NOT NULL,
    evidence_seq      BIGINT NOT NULL,
    cutoff            TIMESTAMPTZ NOT NULL,
    pruned_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT audit_chain_prunes_hash_present CHECK (boundary_hash <> '')
);

CREATE INDEX IF NOT EXISTS audit_chain_prunes_through_idx
    ON audit_chain_prunes (through_seq DESC);
