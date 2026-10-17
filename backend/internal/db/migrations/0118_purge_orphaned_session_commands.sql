-- Remove indexed commands whose recording no longer exists.
--
-- session_commands are the keystrokes of a recording, reconstructed and stored as
-- plaintext rows so the Commands tab can search them. They cascaded only from
-- ssh_sessions, never from session_recordings, so deleting a recording -- by hand or
-- by recording retention -- removed the encrypted file and kept every command typed
-- in it. Session rows are kept far longer than recordings (activity retention is off
-- by default), so on the deployment that found this, commands were still searchable
-- three months after their recordings had been pruned, including a secret typed on a
-- command line. Each one offered a Replay button that could only answer "No recording
-- is available for this session".
--
-- The store now deletes the commands with their recording (DeleteRecordingBySession,
-- PruneRecordingsBefore). This removes what earlier deletions left behind: every
-- command row whose session has no recording. The indexer only ever creates commands
-- from a recording, so there is no legitimate row of that shape to keep.
--
-- Irreversible by design: the rows are what the operator already chose to delete.
--
-- session_commands has FORCE ROW LEVEL SECURITY. A migration's connection may not
-- carry the bypass the application sets, and under RLS this DELETE would silently
-- skip every other tenant's rows. Set it for this transaction only.
SELECT set_config('app.tenant_id', 'bypass', true);

DELETE FROM session_commands sc
WHERE NOT EXISTS (
    SELECT 1 FROM session_recordings r WHERE r.ssh_session_id = sc.ssh_session_id
);
