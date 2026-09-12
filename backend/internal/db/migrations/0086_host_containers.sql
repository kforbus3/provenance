-- What containers each host is actually running.
--
-- Nothing in this product knew a container existed. Vulnerability scanning reads
-- the host's package database, so a machine running twenty containers was, to
-- Provenance, a machine with almost nothing on it -- the packages inside every
-- image were invisible, and on a container host that is most of the attack
-- surface. The fleet's own docker, ai, containers, gitlab, grafana and prometheus
-- hosts are all in that position.
--
-- It is also the first half of managing those containers rather than only
-- observing them: you cannot roll out an update to something you cannot see.
--
-- Collected over the connection the monitor already holds, on the same hourly TTL
-- as pending updates and bound sockets. JSONB for the same reason those are: a
-- bounded list, read whole, never queried by element.
ALTER TABLE host_inventory ADD COLUMN IF NOT EXISTS containers JSONB;
ALTER TABLE host_inventory ADD COLUMN IF NOT EXISTS containers_checked_at TIMESTAMPTZ;

-- Why the host could not be asked, when it could not be asked.
--
-- "No containers" and "we were not allowed to look" must never render the same.
-- Docker's socket is root-owned and the monitor deliberately runs without sudo,
-- so a host where the fleet account is not in the docker group answers nothing --
-- and an empty list there would read as a clean host rather than an unanswered
-- question. This records which it was, so the UI can say so.
ALTER TABLE host_inventory ADD COLUMN IF NOT EXISTS containers_status TEXT NOT NULL DEFAULT '';
