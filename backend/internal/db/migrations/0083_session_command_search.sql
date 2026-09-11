-- Make command search use an index.
--
-- The search matches a term two ways on purpose -- as a full-text query so
-- "systemctl restart" works, and as a raw substring so "rm -rf" does:
--
--   WHERE to_tsvector('simple', command_text) @@ plainto_tsquery('simple', $1)
--      OR command_text ILIKE '%' || $1 || '%'
--
-- The GIN full-text index below has always existed. It could never be used.
-- Postgres cannot build a bitmap over an OR unless BOTH branches are indexable,
-- and `ILIKE '%…%'` is not without trigrams -- so the planner fell back to a
-- sequential scan of the whole table for every search, including one that
-- matches nothing.
--
-- session_commands holds one row per command typed in every recorded session.
-- It is among the fastest-growing tables here, and it has no retention path of
-- its own: a session's commands survive the session while a recording exists.
-- So the table this scans is the one most likely to be enormous.
--
-- pg_trgm makes the substring branch indexable, which makes the OR a BitmapOr
-- over two indexes instead of a seq scan. The extension is not enabled by
-- default; CREATE EXTENSION is idempotent and needs rights the migration runner
-- already has for everything else it does here.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_session_commands_text_trgm
    ON session_commands USING GIN (command_text gin_trgm_ops);

-- The hostname filter is the same shape and the same problem: an optional
-- `hostname ILIKE '%…%'` ANDed onto the above, unindexable, narrowing nothing
-- until every row had already been read.
CREATE INDEX IF NOT EXISTS idx_session_commands_hostname_trgm
    ON session_commands USING GIN (hostname gin_trgm_ops);
