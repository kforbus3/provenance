-- Per-user UI preferences: a small key/value store for personalizations that should
-- follow a user across browsers/devices (e.g. the Dashboard's customizable Quick
-- Connect host list). Values are opaque JSON owned by the frontend. Access is always
-- scoped to the authenticated user's own id, so this table carries no tenant_id.
CREATE TABLE IF NOT EXISTS user_preferences (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key        TEXT NOT NULL,
    value      JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, key)
);
