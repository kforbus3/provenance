-- What a host mounts from another machine, and whether it is itself a guest.
--
-- The dependency graph (0098) is asserted by hand, and the documentation said a
-- host "cannot report that its disks arrive over NFS from a particular NAS". Half
-- of that is wrong: /proc/mounts names the server, in plain text, readable without
-- root. A hand-entered graph that nothing ever checks goes stale silently, and the
-- blast-radius preview and wave ordering built on top of it then state something
-- false with complete confidence. These two columns are the evidence that lets
-- Provenance corroborate an edge, and suggest one nobody has recorded.
--
-- Both keep the inventory contract: NULL means "this sweep did not collect it" and
-- the last-known value is preserved, so a host that could not be asked does not
-- look like a host with no network storage.
ALTER TABLE host_inventory
  ADD COLUMN IF NOT EXISTS network_mounts jsonb,
  ADD COLUMN IF NOT EXISTS mounts_checked_at timestamptz,
  ADD COLUMN IF NOT EXISTS virtualisation text;
