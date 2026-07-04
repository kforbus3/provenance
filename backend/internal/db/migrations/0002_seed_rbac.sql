-- Seed the permission catalog and built-in roles. Idempotent via ON CONFLICT.

INSERT INTO permissions(key, description) VALUES
    ('Host.View',              'View hosts and inventory'),
    ('Host.Connect',           'Open SSH terminals to authorized hosts'),
    ('Host.Enroll',            'Enroll new hosts'),
    ('Host.Edit',              'Edit host metadata'),
    ('Host.Delete',            'Delete hosts'),
    ('Host.RotateCertificate', 'Rotate host certificates'),
    ('Session.Start',          'Start SSH sessions'),
    ('Session.Terminate',      'Terminate any active session'),
    ('Session.Replay',         'Replay recorded sessions'),
    ('File.Transfer',          'Use SFTP upload/download'),
    ('Audit.View',             'View audit logs'),
    ('Audit.Export',           'Export audit logs'),
    ('User.Create',            'Create users'),
    ('User.Edit',              'Edit users'),
    ('User.Delete',            'Delete users'),
    ('User.ResetPassword',     'Reset user passwords / MFA'),
    ('Group.Create',           'Create groups'),
    ('Group.Edit',             'Edit groups'),
    ('Group.Delete',           'Delete groups'),
    ('Role.Create',            'Create roles'),
    ('Role.Edit',              'Edit roles'),
    ('Role.Delete',            'Delete roles'),
    ('Approval.Request',       'Request just-in-time access'),
    ('Approval.Decide',        'Approve or deny access requests'),
    ('Certificate.Manage',     'Manage CA and certificate lifecycle'),
    ('System.Configure',       'Configure system settings'),
    ('Admin.All',              'Full administrative access')
ON CONFLICT (key) DO NOTHING;

INSERT INTO roles(name, description, is_builtin) VALUES
    ('Super Administrator', 'Unrestricted access to everything', true),
    ('Administrator',       'Manage hosts, users, groups, certificates', true),
    ('Operator',            'Connect to hosts and transfer files', true),
    ('Auditor',             'Read-only access to audit and sessions', true),
    ('Read-Only',           'View hosts and inventory only', true)
ON CONFLICT (name) DO NOTHING;

-- Super Administrator -> Admin.All (the enforcement layer treats Admin.All as a wildcard).
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Admin.All' FROM roles r WHERE r.name = 'Super Administrator'
ON CONFLICT DO NOTHING;

-- Administrator -> everything except the Admin.All wildcard.
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, p.key FROM roles r CROSS JOIN permissions p
WHERE r.name = 'Administrator' AND p.key <> 'Admin.All'
ON CONFLICT DO NOTHING;

-- Operator -> connect, sessions, files, view, request approval.
-- Deliberately NOT granted Session.Replay: replay is an oversight capability
-- (Auditor/Admin) — an operator should not watch other users' recorded sessions.
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, p.key FROM roles r CROSS JOIN permissions p
WHERE r.name = 'Operator'
  AND p.key IN ('Host.View','Host.Connect','Session.Start','File.Transfer','Approval.Request')
ON CONFLICT DO NOTHING;

-- Auditor -> view audit, replay sessions, view hosts.
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, p.key FROM roles r CROSS JOIN permissions p
WHERE r.name = 'Auditor'
  AND p.key IN ('Host.View','Audit.View','Audit.Export','Session.Replay')
ON CONFLICT DO NOTHING;

-- Read-Only -> view hosts.
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, p.key FROM roles r CROSS JOIN permissions p
WHERE r.name = 'Read-Only' AND p.key IN ('Host.View')
ON CONFLICT DO NOTHING;

-- Default system settings.
INSERT INTO settings(key, value) VALUES
    ('password_policy', '{"min_length":12,"require_upper":true,"require_lower":true,"require_digit":true,"require_symbol":true,"history":5}'),
    ('lockout_policy',  '{"max_failed":5,"lockout_minutes":15}'),
    ('session_policy',  '{"idle_minutes":30,"absolute_hours":12}')
ON CONFLICT (key) DO NOTHING;
