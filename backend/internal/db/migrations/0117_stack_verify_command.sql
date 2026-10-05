-- A command that proves a managed stack WORKS, not merely that it is up.
--
-- Everything a rollout can read for itself -- state, healthcheck, restart count,
-- and since 0116 the logs -- describes the container. None of it exercises the
-- service. On 2026-10-04 a speech-to-text container was running, healthy, never
-- restarted and failing every request; the traceback reached the log only when
-- the first real request arrived, hours after the rollout. The only check that
-- would have caught it in the soak is one that sends a request.
--
-- So an operator may give a stack a verify command: a shell command run on the
-- host, in the stack's directory, as root. Exit 0 means working. The rollout's
-- soak re-check runs it on each canary and halts on a non-zero exit; the
-- post-rollout watch runs it on every read and raises the regression once.
-- Empty means the stack has none, which is the default and the previous state.
ALTER TABLE container_stacks
    ADD COLUMN IF NOT EXISTS verify_command text NOT NULL DEFAULT '';
