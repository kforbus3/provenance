-- Searchable index of the commands users typed in recorded SSH terminal sessions,
-- reconstructed from the asciicast input events by a background indexer. This makes
-- "who ran command X" answerable without replaying every recording. It is a
-- BEST-EFFORT reconstruction (a raw PTY keystroke stream), so it is for search, not a
-- forensically exact executed-command log.
CREATE TABLE IF NOT EXISTS session_commands (
    id             BIGSERIAL PRIMARY KEY,
    ssh_session_id UUID NOT NULL REFERENCES ssh_sessions(id) ON DELETE CASCADE,
    user_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    host_id        UUID REFERENCES hosts(id) ON DELETE SET NULL,
    username       TEXT NOT NULL DEFAULT '',   -- denormalized for display + search
    hostname       TEXT NOT NULL DEFAULT '',
    ts             TIMESTAMPTZ NOT NULL,        -- when the command was submitted
    command_text   TEXT NOT NULL
);

-- Full-text index for word/phrase search, plus a trigram-free fallback via ILIKE on
-- command_text (the GIN FTS covers the common "contains a word" queries efficiently).
CREATE INDEX IF NOT EXISTS idx_session_commands_fts
    ON session_commands USING GIN (to_tsvector('simple', command_text));
CREATE INDEX IF NOT EXISTS idx_session_commands_session ON session_commands(ssh_session_id);
CREATE INDEX IF NOT EXISTS idx_session_commands_host ON session_commands(host_id);
CREATE INDEX IF NOT EXISTS idx_session_commands_ts ON session_commands(ts DESC);

-- Marker so the indexer processes each recording exactly once (NULL = not yet indexed).
ALTER TABLE session_recordings ADD COLUMN IF NOT EXISTS commands_indexed_at TIMESTAMPTZ;
