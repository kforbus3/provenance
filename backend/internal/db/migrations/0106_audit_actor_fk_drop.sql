-- Deleting a user rewrote that user's audit history and broke the hash chain.
--
-- audit_events.actor_id carried
--
--   FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
--
-- and actor_id is part of the canonical record the chain hashes (see
-- auditCanonicalHMAC). So DELETE /api/v1/users/{id} -- an ordinary action behind
-- the User.Delete permission, which is what offboarding somebody is -- silently
-- set actor_id to NULL on every event that user had ever produced, changing rows
-- the chain had already sealed. The chain then reports broken at the first of
-- them, permanently, and the compliance evidence pack reports
--
--   FAIL - the audit chain is broken at sequence N
--   Events on or after that point may have been altered or removed and must be
--   investigated before this pack is relied upon as evidence.
--
-- The chain was right. Rows had been altered. The defect is that the schema let a
-- routine administrative act alter them.
--
-- Found by deleting a test account during an SSO test and then generating an
-- evidence pack for an unrelated reason.
--
-- An audit log is an append-only historical record and must not be
-- referentially bound to a mutable table: actor_name is already stored beside
-- actor_id precisely so each row describes its actor without a join. RESTRICT
-- would have been the other option and is worse -- it makes a user with any
-- history undeletable, which is a different way to fail an offboarding request.
--
-- Rows already NULLed cannot be recovered; the break they caused is permanent and
-- is what the acknowledgement mechanism in 0105 exists for.
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_actor_id_fkey;

COMMENT ON COLUMN audit_events.actor_id IS
    'The acting user at the time of the event. Deliberately NOT a foreign key: '
    'an audit row is immutable history and must not change when the users table '
    'does. May reference a user that no longer exists; actor_name is stored '
    'alongside so the row stands on its own.';
