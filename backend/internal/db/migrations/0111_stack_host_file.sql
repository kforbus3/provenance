-- What a managed stack's compose file on its host actually says, as last read.
--
-- Drift compared revision numbers only: the stored revision against the one the host
-- last confirmed deploying. A change made on the host itself leaves both at the same
-- number, so it was invisible -- and the next Deploy re-applied the stored copy over
-- it. That is how Keycloak went down on 2026-09-20, and on 2026-09-24 its stored
-- copy was still the plain-HTTP configuration it had been moved off two days before,
-- with both sides reading revision 5.
--
-- Only a hash is kept. The monitor reads the file to hash it; the contents (which
-- can carry secrets) are never stored.
ALTER TABLE container_stacks
    ADD COLUMN IF NOT EXISTS host_compose_sha text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS host_checked_at timestamptz,
    ADD COLUMN IF NOT EXISTS host_check_error text NOT NULL DEFAULT '';
