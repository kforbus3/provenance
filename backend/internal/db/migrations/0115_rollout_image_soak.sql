-- Canary and soak per image, not per rollout.
--
-- A rollout covering every available update ("Update All") proved the first host's
-- images, then held every other host back for the soak -- including hosts running
-- images that first host never touched, which then went out unproven anyway once
-- the soak ran out. The rollout-level canary_done_at (0090) stays for rollouts made
-- before this; each image now carries its own.
--
--   canary_done_at   when this image's canary hosts had all verified
--   soak_checked_at  when, after the soak ran out, those canaries were re-checked
--                    and found still running and healthy. NULL until then; the
--                    image's other hosts wait for it.
ALTER TABLE container_update_rollout_images
  ADD COLUMN IF NOT EXISTS canary_done_at  timestamptz,
  ADD COLUMN IF NOT EXISTS soak_checked_at timestamptz;
