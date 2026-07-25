-- Federation upgrade ordering: track each site's running BUILD version (fleetd
-- version, refreshed on the read-model heartbeat) and its federation PROTOCOL version
-- (negotiated at join). Build version gives the hub visibility into version skew and
-- lets it enforce sites-first upgrade ordering; protocol version lets the hub reject a
-- site speaking an incompatible federation wire protocol. (api_version was a dead
-- field — left in place; these supersede it.)
ALTER TABLE federation_sites ADD COLUMN IF NOT EXISTS build_version TEXT NOT NULL DEFAULT '';
ALTER TABLE federation_sites ADD COLUMN IF NOT EXISTS protocol_version INT NOT NULL DEFAULT 0;
