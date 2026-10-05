-- A watch on every container a rollout has just updated.
--
-- The end-of-soak re-check (0115) proves a container is running, not unhealthy and
-- not restarted. On 2026-10-04 a speech-to-text image passed all three and then
-- failed every request it was given: the new build carried a library that had
-- dropped an argument the application still passed, the error surfaced only when
-- real traffic arrived three hours after the rollout, and the healthcheck -- a port
-- probe -- kept answering. Nothing in Provenance could have noticed, because
-- nothing read the container's logs, and nothing looked at the container at all
-- once the rollout had completed.
--
-- One row per (rollout, host, image). The engine tails the container's logs on a
-- cadence until expires_at, looking for error traces. The first one found is
-- recorded here and raised as container.rollout.regression, once.
--
--   checked_at     the log cursor: the next read starts here
--   regression     what was found, "" while nothing has been
--   regression_at  when it was found; set once, the watch then stops reading
CREATE TABLE IF NOT EXISTS container_update_rollout_watches (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  rollout_id    uuid NOT NULL REFERENCES container_update_rollouts(id) ON DELETE CASCADE,
  host_id       uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  repository    text NOT NULL,
  to_tag        text NOT NULL,
  started_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  checked_at    timestamptz NOT NULL DEFAULT now(),
  regression    text NOT NULL DEFAULT '',
  regression_at timestamptz,
  UNIQUE (rollout_id, host_id, repository)
);

CREATE INDEX IF NOT EXISTS container_update_rollout_watches_due
  ON container_update_rollout_watches (checked_at)
  WHERE regression_at IS NULL;
