-- What a person may do to a Kubernetes cluster is decided by their Provenance
-- role, not by the cluster's ServiceAccount.
--
-- Every operator reaches a cluster through one registered credential, so the
-- cluster cannot tell them apart -- to it, every call is the same
-- ServiceAccount. Kubernetes.Access was therefore all-or-nothing: whoever held
-- it could do whatever the cluster's RBAC allowed, identically for an
-- administrator and a read-only operator.
--
-- Access now means READ. These two carry the rest.
INSERT INTO permissions (key, description) VALUES
    ('Kubernetes.Operate',    'Change workloads on a brokered cluster (pods, deployments, jobs, exec)'),
    ('Kubernetes.Administer', 'Administer a brokered cluster: namespaces, CRDs, RBAC, storage, nodes, Secrets')
ON CONFLICT (key) DO NOTHING;

-- Seeded to match what each built-in role could already do, so no built-in role
-- loses capability at this migration:
--   Operator            ran workloads          -> Operate
--   Administrator       administered           -> Operate + Administer
--   Super Administrator everything             -> both (and Admin.All anyway)
INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, 'Kubernetes.Operate' FROM roles r
WHERE r.name IN ('Super Administrator', 'Administrator', 'Operator')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, 'Kubernetes.Administer' FROM roles r
WHERE r.name IN ('Super Administrator', 'Administrator')
ON CONFLICT DO NOTHING;

-- A CUSTOM role holding Kubernetes.Access is deliberately NOT upgraded. It
-- could previously write, and after this it reads only -- a real reduction, and
-- the safe direction for a change nobody reviewed. Grant Kubernetes.Operate to
-- restore it; the Roles page lists both new permissions.
