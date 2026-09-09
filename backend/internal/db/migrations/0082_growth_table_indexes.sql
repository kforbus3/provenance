-- Indexes for the tables that grow without bound and were being scanned.
--
-- These tables accumulate a row per session, per transfer, per scan, for the
-- life of the deployment. Every query below currently does a sequential scan,
-- which is free on a database a week old and is not on one a year old -- and
-- retention ships off by default, so nothing removes the rows underneath them.
--
-- CONCURRENTLY is deliberately NOT used: the migration runner wraps each file
-- in a transaction and CREATE INDEX CONCURRENTLY cannot run inside one. These
-- tables are append-only and the writes are short, so a brief lock at upgrade
-- time is the cheaper trade. IF NOT EXISTS keeps the file idempotent.

-- sftp_transfers had no index at all beyond its primary key -- not one, in 86
-- migrations -- while being queried by session, by user, by host, and by time.
-- The session/user/host lookups all sort by created_at, so the index carries it
-- rather than making Postgres sort the result.
CREATE INDEX IF NOT EXISTS idx_sftp_transfers_session
    ON sftp_transfers (ssh_session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sftp_transfers_user
    ON sftp_transfers (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sftp_transfers_host
    ON sftp_transfers (host_id, created_at DESC);
-- Retention pruning and the CSV export both range over created_at alone.
CREATE INDEX IF NOT EXISTS idx_sftp_transfers_created
    ON sftp_transfers (created_at);

-- session_recordings: pruned by created_at, and the command indexer sweeps for
-- recordings it has not read yet. The indexer's index is partial, so it holds
-- only the rows still outstanding rather than one entry per recording ever
-- made -- the set it looks for is the small one.
CREATE INDEX IF NOT EXISTS idx_session_recordings_created
    ON session_recordings (created_at);
CREATE INDEX IF NOT EXISTS idx_session_recordings_unindexed
    ON session_recordings (created_at)
    WHERE commands_indexed_at IS NULL;

-- ssh_sessions: retention prunes on ended_at, and the recordings view filters
-- on status.
CREATE INDEX IF NOT EXISTS idx_ssh_sessions_ended
    ON ssh_sessions (ended_at);
CREATE INDEX IF NOT EXISTS idx_ssh_sessions_status
    ON ssh_sessions (status, started_at DESC);

-- audit_events: the list filters created_at but orders by seq, so an index on
-- created_at alone cannot serve the sort and Postgres sorts the whole filtered
-- set. seq is monotonic with created_at -- it is the append order of the same
-- rows -- so this one index answers both halves.
CREATE INDEX IF NOT EXISTS idx_audit_created_seq
    ON audit_events (created_at, seq DESC);

-- Session expiry: revoking stamps revoked_at rather than deleting, so this
-- table keeps every session ever issued and is swept for stale ones.
CREATE INDEX IF NOT EXISTS idx_sessions_last_seen
    ON sessions (last_seen_at);
