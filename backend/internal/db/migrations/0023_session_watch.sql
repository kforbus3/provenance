-- Live session shadowing: a read-only, real-time view of an active terminal
-- session for four-eyes oversight. Gated by a dedicated permission so it can be
-- granted independently of after-the-fact replay.

INSERT INTO permissions(key, description) VALUES
    ('Session.Watch', 'Watch active terminal sessions live (read-only oversight)')
ON CONFLICT (key) DO NOTHING;

-- Grant to the roles that already perform session oversight.
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Session.Watch' FROM roles r
WHERE r.name IN ('Super Administrator', 'Administrator', 'Auditor')
ON CONFLICT DO NOTHING;
