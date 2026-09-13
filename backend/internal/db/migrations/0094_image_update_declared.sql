-- Records whether a row's tag came from a compose file rather than a running
-- container.
--
-- Without it the two cannot be told apart in the UI, and they need different
-- treatment. A container running :latest whose compose file names
-- v1.6.0-ls356 produces two rows: the running one reports "rebuilt" forever,
-- because the tag really has moved, while a rollout of it can only ever skip --
-- the host's compose has moved past :latest, so the image is superseded and
-- nothing is recreated. The row that CAN be applied is the declared one, and
-- applying it is what finally moves the container off :latest.
--
-- Defaults false, so existing rows read as running-container rows, which is
-- what every one of them was before this column existed.
ALTER TABLE container_image_updates
    ADD COLUMN IF NOT EXISTS declared boolean NOT NULL DEFAULT false;
