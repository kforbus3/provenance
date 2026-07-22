-- Kubernetes access brokering: register clusters and reach their API server through
-- Fleet, which injects a vaulted bearer-token credential (the operator never sees it)
-- and audits every call. Fleet acts as an authenticating proxy, so a user's kubectl (or
-- the built-in resource browser) authenticates to Fleet, and Fleet authenticates to the
-- cluster. Mirrors the database broker.
CREATE TABLE IF NOT EXISTS k8s_clusters (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT NOT NULL,
    api_server    TEXT NOT NULL,                       -- https://host:6443
    credential_id UUID REFERENCES vault_secrets(id) ON DELETE SET NULL, -- vault secret holding a bearer token
    ca_cert       TEXT NOT NULL DEFAULT '',            -- PEM CA bundle to verify the API server TLS (empty = system roots)
    insecure_tls  BOOLEAN NOT NULL DEFAULT false,      -- skip API-server TLS verification (test clusters only)
    namespace     TEXT NOT NULL DEFAULT 'default',     -- default namespace for the resource browser
    description   TEXT NOT NULL DEFAULT '',
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_k8s_clusters_name ON k8s_clusters(name);

INSERT INTO permissions(key, description) VALUES
    ('Kubernetes.Manage', 'Register, edit, and delete Kubernetes cluster targets'),
    ('Kubernetes.Access', 'Reach a brokered Kubernetes cluster (proxy / resource browser)')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Kubernetes.Manage' FROM roles r WHERE r.name IN ('Super Administrator', 'Administrator')
ON CONFLICT DO NOTHING;
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Kubernetes.Access' FROM roles r WHERE r.name IN ('Super Administrator', 'Administrator', 'Operator')
ON CONFLICT DO NOTHING;
