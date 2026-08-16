-- Branding: customizable application name shown in the UI (login, top bar,
-- dashboard, browser title). Stored as a setting so admins can change it at
-- runtime with no rebuild. Served publicly (unauthenticated) via /version so the
-- login and bootstrap screens can display it.

INSERT INTO settings(key, value) VALUES
    ('branding', '{"app_name":"Moorgate"}')
ON CONFLICT (key) DO NOTHING;
