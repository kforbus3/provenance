-- AI assistant: a read-only, RBAC-scoped natural-language query layer over fleet
-- data, backed by a local Ollama instance. Opt-in via the `assistant` setting.

INSERT INTO permissions(key, description) VALUES
    ('Assistant.Use', 'Use the AI assistant to query fleet data (read-only)')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Assistant.Use' FROM roles r
WHERE r.name IN ('Administrator', 'Operator')
ON CONFLICT DO NOTHING;

-- Disabled until an admin points it at a local Ollama instance and picks a model.
INSERT INTO settings(key, value) VALUES
    ('assistant', '{"enabled":false,"ollamaUrl":"","model":""}')
ON CONFLICT (key) DO NOTHING;
