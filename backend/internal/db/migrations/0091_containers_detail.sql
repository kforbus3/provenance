-- WHY the container list is empty, not just that it is.
--
-- containers_status says "no_access", which tells an operator something is wrong
-- and nothing about what to do — and its two causes need opposite actions: an
-- account that is not in the socket's group is a one-line fix, a daemon that is
-- not running is a different problem. Six hosts on a nineteen-host fleet said
-- no_access with no way to tell which, and working that out meant an SSH session
-- per host.
ALTER TABLE host_inventory ADD COLUMN IF NOT EXISTS containers_detail TEXT NOT NULL DEFAULT '';
