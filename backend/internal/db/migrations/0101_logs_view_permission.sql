-- The Logs page: search the Aldgate collector from inside Provenance.
--
-- Read-only by design. There is no permission here for changing a log, because
-- changing a log is not something an audit trail should offer; retention is the
-- collector's business.
INSERT INTO permissions (key, description) VALUES
    ('Logs.View', 'Search collected logs from the whole fleet')
ON CONFLICT (key) DO NOTHING;

-- Seeded to the roles that can already reach hosts interactively: anyone who can
-- open a shell on a machine can already read its logs there, so withholding the
-- collected copy would protect nothing and only make the collector less useful.
INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, 'Logs.View' FROM roles r
WHERE r.name IN ('Super Administrator', 'Administrator', 'Operator', 'Auditor')
ON CONFLICT DO NOTHING;
