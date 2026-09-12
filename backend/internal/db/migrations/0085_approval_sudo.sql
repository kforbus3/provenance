-- Just-in-time root: an access request may ask for sudo, and an approval may
-- grant it for a bounded time.
--
-- Host.Sudo decides which account a connection lands in -- the privileged shared
-- account (NOPASSWD sudo) or the login-only one -- and it is a live permission
-- check with nothing else feeding it. So the only way a login-only user could
-- ever get root was for an administrator to grant their ROLE Host.Sudo: fleet
-- wide, indefinite, and with no mechanism to take it back. In practice that
-- leaves two outcomes, and both defeat the tier: either operators hold
-- Host.Sudo permanently, or they are granted it once and it never comes off.
--
-- Everything needed for the bounded version already existed. approval_requests
-- records a reason, a ticket reference, a requested and a granted duration, and
-- who decided; approving one atomically inserts a temporary_permissions row with
-- an expires_at. That is time-boxed, scoped to a host or a group, attributable,
-- and requires a second person. It simply had no notion of privilege -- an
-- approved request got you onto the host and said nothing about which account.
--
-- Two booleans is the whole change: what was asked for, and what was granted.
-- They are separate on purpose. An approver may grant the access and withhold
-- the root, which is a decision worth being able to make and worth recording.
ALTER TABLE approval_requests
    ADD COLUMN IF NOT EXISTS sudo BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE temporary_permissions
    ADD COLUMN IF NOT EXISTS sudo BOOLEAN NOT NULL DEFAULT false;

-- The lookup on the connection path is "has this user an unexpired, unrevoked
-- sudo grant for this host", run on every connect. Existing indexes cover
-- user_id and expires_at; this one makes the sudo-only subset cheap without
-- widening either.
CREATE INDEX IF NOT EXISTS idx_temp_perms_sudo_active
    ON temporary_permissions(user_id, host_id)
    WHERE sudo AND revoked_at IS NULL;
