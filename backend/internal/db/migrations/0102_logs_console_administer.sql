-- Two tiers for the embedded log console, so the level of access somebody gets
-- inside Dashboards follows their Provenance role.
--
-- Until now the console was a raw proxy to Dashboards with no Provenance
-- authentication at all: it asked for its own username and password, and a
-- Provenance role had no bearing on what you could do once you were in. Anyone
-- who could reach the Provenance frontend could reach the console's own login
-- page, and anyone who knew the collector's admin password had everything.
--
-- Logs.View now opens the console read-only -- it can search and build
-- visualisations and cannot change an index, a policy or a saved object.
-- Logs.Administer is the full console: index management, retention policies, the
-- collector's own security settings.
INSERT INTO permissions (key, description) VALUES
    ('Logs.Administer', 'Manage the log collector from the embedded console: indices, retention and its own settings')
ON CONFLICT (key) DO NOTHING;

-- Deliberately NOT given to Operator or Auditor, both of which hold Logs.View.
-- Reading every host's logs is the job; being able to delete an index or rewrite
-- a retention policy is administering the audit trail itself, which is a
-- different thing and belongs with the people who own the platform.
INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, 'Logs.Administer' FROM roles r
WHERE r.name IN ('Super Administrator', 'Administrator')
ON CONFLICT DO NOTHING;
