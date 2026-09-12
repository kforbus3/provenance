-- Remove the command runner's trailing marker from stored compose files.
--
-- An adoption swallowed "[exit code 0]" -- the line internal/command appends to
-- every result -- into the compose content it saved. The intake is fixed, but a
-- record already poisoned stays poisoned, and the deploy writes the STORED copy:
-- so every subsequent attempt rewrote the same unparseable file onto the host,
-- and the host stayed broken however many times it was retried.
--
-- Anchored to the end of the value, so a compose file that legitimately mentions
-- the phrase somewhere in a comment or a command is untouched.
UPDATE container_stacks
SET compose = regexp_replace(compose, E'\n*\\[exit code [0-9]+\\]\\s*$', E'\n')
WHERE compose ~ E'\\[exit code [0-9]+\\]\\s*$';

UPDATE container_stack_revisions
SET compose = regexp_replace(compose, E'\n*\\[exit code [0-9]+\\]\\s*$', E'\n')
WHERE compose ~ E'\\[exit code [0-9]+\\]\\s*$';
