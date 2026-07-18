-- Assistant actions: the propose→confirm→execute lifecycle for actions the AI
-- assistant suggests. The assistant never executes on its own — a proposal is
-- staged here (status 'proposed'), the user explicitly confirms it, and only then
-- is it executed, re-authorized against the live principal at execution time.
-- This table is the proposal store and the history/audit trail of assistant-
-- initiated actions.

CREATE TABLE IF NOT EXISTS assistant_actions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,  -- who the assistant is acting as
    kind        TEXT NOT NULL,                       -- registered action kind, e.g. scan.vulnerability
    params      JSONB NOT NULL DEFAULT '{}',         -- resolved action parameters
    preview     TEXT NOT NULL DEFAULT '',            -- human-readable description of what will happen
    risk        TEXT NOT NULL DEFAULT 'safe',        -- safe | guarded | destructive
    permission  TEXT NOT NULL DEFAULT '',            -- permission required to execute
    status      TEXT NOT NULL DEFAULT 'proposed',    -- proposed | executed | failed | cancelled | expired
    outcome     TEXT NOT NULL DEFAULT '',            -- result summary after execution
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,                -- a proposal not confirmed by now is void
    executed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_assistant_actions_user ON assistant_actions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_assistant_actions_status ON assistant_actions(status);

-- Gate for using the assistant's actionable features at all. This is ON TOP of the
-- per-action permission (e.g. Host.Scan) — a user needs both. Deliberately withheld
-- from read-only/auditor roles.
INSERT INTO permissions(key, description) VALUES
    ('Assistant.Act', 'Let the assistant propose actions you can confirm and execute')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Assistant.Act' FROM roles r
WHERE r.name IN ('Super Administrator', 'Administrator', 'Operator')
ON CONFLICT DO NOTHING;
