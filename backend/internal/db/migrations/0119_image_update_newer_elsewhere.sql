-- A later release published under a different tag format than the one running.
--
-- jellyfin went from 10.11.11 to 12.0 and now tags releases 12.4, so no tag of
-- the running shape will ever be newer and the image read as up to date with five
-- releases out. The checker now finds those, and they need a column of their own
-- rather than latest_tag: latest_tag is what a rollout moves a host TO, and a tag
-- of a different numbering is a decision about which line to be on, not an
-- update to roll out.
ALTER TABLE container_image_updates
    ADD COLUMN IF NOT EXISTS newer_elsewhere text NOT NULL DEFAULT '';
