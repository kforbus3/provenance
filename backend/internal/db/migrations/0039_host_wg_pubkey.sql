-- Persist each managed host's WireGuard public key. It was previously used only
-- transiently during enrollment (to add the host as a peer on the jump host) and
-- then discarded. Storing it lets a STANDBY jump host rebuild the overlay peer list
-- from Postgres on failover (High Availability), instead of the peer set living only
-- in the active jump host's wg runtime state.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS wg_public_key TEXT NOT NULL DEFAULT '';
