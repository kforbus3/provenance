-- Revoke Session.Replay from the built-in Operator role on existing installs.
--
-- Session.Replay is enforced as a global "view any recorded session" grant (no
-- per-user ownership scoping), so an Operator holding it can watch every user's
-- sessions — including admins'. Replay is an oversight capability that belongs to
-- Auditor/Admin, not to a hands-on connect-and-transfer role. Fresh installs no
-- longer seed this (see 0002_seed_rbac.sql); this brings already-provisioned
-- databases in line.
--
-- Guarded to the built-in Operator role (is_builtin = true) so a custom role that
-- happens to be named "Operator", or the built-in role after an admin renamed it,
-- is left untouched. If an admin deliberately re-adds Session.Replay to Operator
-- later, this migration will not run again to remove it.
DELETE FROM role_permissions
WHERE permission_key = 'Session.Replay'
  AND role_id IN (SELECT id FROM roles WHERE name = 'Operator' AND is_builtin = true);
