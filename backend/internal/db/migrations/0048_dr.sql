-- Disaster recovery: a dedicated permission for the DR console (status +
-- administrator-triggered failover/failback). DR actions are the highest-impact
-- controls in the product (they hand the writable role between sites), so they get
-- their own permission — Super Administrator + Administrator by default — rather
-- than riding on System.Configure.
INSERT INTO permissions(key, description) VALUES
    ('DR.Manage', 'View disaster-recovery status and trigger failover/failback')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'DR.Manage' FROM roles r WHERE r.name IN ('Super Administrator', 'Administrator')
ON CONFLICT DO NOTHING;
