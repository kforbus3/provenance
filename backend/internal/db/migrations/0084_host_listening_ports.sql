-- What each host is actually listening on.
--
-- Vulnerability scanning answers "which installed packages have CVEs" by reading
-- the package database. It cannot answer "is any of that reachable", because it
-- never looks at the network. Compliance scanning checks configuration against a
-- benchmark, which is a different question again. So a finding of "openssl has
-- CVE-X" arrives with no way to tell whether the host exposes it to anything.
--
-- Collected over the connection the monitor already has, on the same hourly TTL
-- as pending updates -- not on every sweep. JSONB for the same reason
-- update_packages and obsolete_packages are: it is a bounded list read whole and
-- never queried by element.
ALTER TABLE host_inventory ADD COLUMN IF NOT EXISTS listening_ports JSONB;
ALTER TABLE host_inventory ADD COLUMN IF NOT EXISTS ports_checked_at TIMESTAMPTZ;
