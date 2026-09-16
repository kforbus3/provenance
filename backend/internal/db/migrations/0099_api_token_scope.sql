-- A token that can only do one job.
--
-- api_tokens.service_account_id has always been a foreign key to users(id);
-- "service account" is a FLAG on the user row, not a separate table. So a token
-- belonging to a real person needs no schema change at all -- only the lookup
-- query's `AND u.is_service_account` predicate stands in the way.
--
-- What does need adding is a limit on what such a token may reach. A token in a
-- kubeconfig sits in a file on a laptop, and without a scope it carries its
-- owner's ENTIRE permission set with no MFA and no session behind it -- every
-- host, every credential, every playbook. That is a bad trade for the ability to
-- run kubectl.
--
-- NULL means unscoped, which is what every existing token is and what service
-- account tokens continue to be: this changes nothing that already works.
ALTER TABLE api_tokens
  ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN api_tokens.scope IS
  'Empty = unscoped (full permissions of the owner). Otherwise an API path prefix the token is confined to, e.g. /api/v1/k8s/.';

-- Who the token belongs to is already expressed by service_account_id; the name
-- is now misleading rather than wrong. Renaming it would touch every query and
-- every caller for no behavioural gain, so it is documented instead.
COMMENT ON COLUMN api_tokens.service_account_id IS
  'Owner. A users(id) row, which may be a service account (users.is_service_account) or a real person.';
