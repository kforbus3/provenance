-- What a registry says is available for an image the fleet is running.
--
-- This is the half a renovate bot did: ask the registry whether the tag a host is
-- running still points at the digest it is running, and whether a newer tag
-- exists. Keyed by repository and tag because that pair is what a registry
-- answers about -- the digest is the ANSWER, not the question.
--
-- Kept apart from container_image_scans on purpose. That table says what is wrong
-- with the bytes a host has; this one says whether newer bytes exist. They change
-- for different reasons, on different schedules, and conflating them would mean
-- re-pulling an image to discover a tag had moved.
CREATE TABLE IF NOT EXISTS container_image_updates (
    repository     TEXT NOT NULL,
    tag            TEXT NOT NULL,
    -- What the tag points at NOW. A tag moves; this is the whole reason to ask.
    current_digest TEXT NOT NULL DEFAULT '',
    -- A newer tag, when one was found and could be ordered confidently. Empty is
    -- a real answer: "nothing newer" and "the tags here cannot be ordered" are
    -- different, and the second is recorded in note rather than guessed at.
    latest_tag     TEXT NOT NULL DEFAULT '',
    note           TEXT NOT NULL DEFAULT '',
    error          TEXT NOT NULL DEFAULT '',
    checked_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (repository, tag)
);

CREATE INDEX IF NOT EXISTS idx_image_updates_checked ON container_image_updates(checked_at);
