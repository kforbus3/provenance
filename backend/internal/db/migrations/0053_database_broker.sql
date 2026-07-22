-- Database access brokering: register database targets and run brokered SQL sessions
-- through the jump host with a vaulted credential injected (the operator never sees the
-- password) and every query audited. Postgres in this first version.
CREATE TABLE IF NOT EXISTS databases (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT NOT NULL,
    engine        TEXT NOT NULL DEFAULT 'postgres' CHECK (engine IN ('postgres')),
    address       TEXT NOT NULL,                       -- host reachable from the jump host
    port          INT  NOT NULL DEFAULT 5432,
    database_name TEXT NOT NULL DEFAULT 'postgres',    -- the database to connect to
    credential_id UUID REFERENCES vault_secrets(id) ON DELETE SET NULL, -- vault password (user+secret)
    description   TEXT NOT NULL DEFAULT '',
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_databases_name ON databases(name);

INSERT INTO permissions(key, description) VALUES
    ('Database.Manage',  'Register, edit, and delete database targets'),
    ('Database.Connect', 'Open a brokered SQL session to a database and run queries')
ON CONFLICT (key) DO NOTHING;

-- Management to administrators; connect also to operators. Auditors excluded.
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Database.Manage' FROM roles r WHERE r.name IN ('Super Administrator', 'Administrator')
ON CONFLICT DO NOTHING;
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Database.Connect' FROM roles r WHERE r.name IN ('Super Administrator', 'Administrator', 'Operator')
ON CONFLICT DO NOTHING;
