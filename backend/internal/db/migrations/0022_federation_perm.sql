-- Register the Federation.Manage permission (add/revoke sites, mint join tokens)
-- and grant it to the built-in Administrator role. Super Administrator already
-- holds it via the Admin.All wildcard. Idempotent.
INSERT INTO permissions(key, description) VALUES
    ('Federation.Manage', 'Manage federated sites (join, revoke, tokens)')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Federation.Manage' FROM roles r
WHERE r.name = 'Administrator' AND r.is_builtin = true
ON CONFLICT DO NOTHING;
