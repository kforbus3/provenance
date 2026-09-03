-- Permissions for the Flipside imaging and OS-update subsystem (docs/imaging.md).
--
-- Two, because looking and changing are genuinely different here. Viewing tells
-- you what operating system every host is running and whether it is behind,
-- which an auditor should have. Managing starts rollouts and installs software
-- on machines, which is the same weight as Command.Run and is granted the same
-- way -- in fact it is enforced through the same gateway, policy and audit path
-- underneath.

INSERT INTO permissions(key, description) VALUES
    ('Imaging.View',   'See OS images, update bundles, rollouts, and each host''s OS version'),
    ('Imaging.Manage', 'Build images and bundles, run rollouts, and install updates on hosts')
ON CONFLICT (key) DO NOTHING;

-- Viewing goes to everyone who can already see the fleet; Auditor included,
-- because "what is every machine running" is an audit question.
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Imaging.View' FROM roles r
WHERE r.name IN ('Administrator', 'Operator', 'Auditor')
ON CONFLICT DO NOTHING;

-- Managing does not. An Operator can already run commands on hosts, so this
-- grants nothing they could not do by hand; an Auditor cannot, and should not
-- acquire the ability to change what a machine runs by way of a feature that
-- sounds like reporting.
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Imaging.Manage' FROM roles r
WHERE r.name IN ('Administrator', 'Operator')
ON CONFLICT DO NOTHING;
