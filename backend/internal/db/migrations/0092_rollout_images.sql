-- A rollout can cover several images at once.
--
-- "Update everything that has something available" was otherwise one rollout per
-- image, started by hand, each pacing itself independently — so ten images meant
-- ten canaries running at the same time on ten different hosts, which is not a
-- canary at all. Pacing has to apply to the whole operation or it does not apply.
--
-- Paced by HOST rather than by image: a host takes every update that applies to
-- it, then the next host follows. That is also how an operator thinks about it —
-- "update my containers, carefully" — and it means one host is either current or
-- it is not, rather than half-updated across a fleet.
CREATE TABLE IF NOT EXISTS container_update_rollout_images (
    rollout_id    UUID NOT NULL REFERENCES container_update_rollouts(id) ON DELETE CASCADE,
    repository    TEXT NOT NULL,
    from_tag      TEXT NOT NULL,
    to_tag        TEXT NOT NULL,
    -- What the registry said the target points at when the rollout was created.
    -- Per image, for the same reason the single-image column exists: a tag that
    -- moves mid-rollout would otherwise leave early hosts on bytes the late ones
    -- never get, with every host reported as verified.
    target_digest TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (rollout_id, repository, from_tag)
);

-- Backfill: every existing rollout becomes a one-image rollout, so the engine has
-- a single path to read rather than two that drift. Without this, rollouts created
-- before this migration would have no images and the engine would find nothing to
-- do for hosts that are legitimately mid-flight.
INSERT INTO container_update_rollout_images (rollout_id, repository, from_tag, to_tag, target_digest)
SELECT id, repository, from_tag, to_tag, target_digest
FROM container_update_rollouts
ON CONFLICT DO NOTHING;
