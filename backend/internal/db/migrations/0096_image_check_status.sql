-- An explicit verdict, and a cache for tag listings.
--
-- `status` exists because the UI was inferring one from the NOTE, and prose is
-- not an API. "nothing newer with the same shape as 10.11.11; the repository
-- carries other version tags that cannot be ordered against it" means the image
-- is up to date -- and rendered as "cannot compare", identical to a check that
-- actually failed. Twenty-two healthy images read as broken. The note text
-- changed twice in one evening, which is exactly why nothing should key off it.
--
-- Empty means "written before this column existed"; the client falls back to
-- reading the note for those, and the next check fills them in.
ALTER TABLE container_image_updates
    ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT '';

-- Tag listings are the expensive part of a check, and they are re-fetched in
-- full on every pass.
--
-- Following pagination made a listing correct and made it cost 10-32 requests
-- per repository instead of one: lscr.io/linuxserver/jackett is 31,667 tags over
-- 32 pages. A forced sweep of the fleet is then several hundred requests to one
-- registry, and pressing the button a few times in an hour rate-limits the
-- instance -- which reports as "could not list tags" against eight images that
-- are perfectly fine.
--
-- A tag list changes when a maintainer publishes, which is not on the timescale
-- of somebody pressing a button twice. Cached per repository, and a rate-limited
-- answer falls back to the cache rather than discarding what is already known.
CREATE TABLE IF NOT EXISTS registry_tag_cache (
    repository  TEXT PRIMARY KEY,
    tags        JSONB       NOT NULL,
    complete    BOOLEAN     NOT NULL DEFAULT true,
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
