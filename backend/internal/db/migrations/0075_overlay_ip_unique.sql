-- Guarantee at most one host per overlay (WireGuard/OpenVPN) address.
--
-- Why: overlay-address allocation now runs under a Postgres advisory lock
-- (Store.ReserveWGAddress) so two backend replicas take turns reading the used set
-- and can never hand out the same free address. This UNIQUE index is the final,
-- storage-level backstop: any code path that writes hosts.wg_address WITHOUT the
-- allocation lock — a manual admin edit, an import, or the legacy
-- NextFreeWGAddress + SetHostWGAddress pair — is now physically prevented from
-- creating a duplicate overlay IP rather than silently colliding two tunnels.
--
-- Partial (WHERE wg_address IS NOT NULL): unassigned hosts keep a NULL wg_address,
-- and many NULLs must remain allowed. A partial unique index also documents that
-- only assigned addresses are constrained.
--
-- If this migration fails, an existing duplicate overlay address is already in the
-- table; resolve it (re-assign one of the colliding hosts) and re-run.
CREATE UNIQUE INDEX IF NOT EXISTS hosts_wg_address_unique
    ON hosts (wg_address)
    WHERE wg_address IS NOT NULL;
