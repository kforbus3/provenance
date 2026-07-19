-- Conditional access: per-user override of the global session policy (IP
-- allowlist + max concurrent sessions). The global policy lives in the settings
-- table under key "session_policy"; this table overrides it per user. A NULL
-- column inherits the global value; an empty ip_allowlist array means "no IP
-- restriction for this user" (explicitly opting out of a global allowlist).
CREATE TABLE IF NOT EXISTS user_session_policies (
    user_id                 UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    ip_allowlist            JSONB,        -- array of CIDR / bare-IP strings; NULL = inherit global
    max_concurrent_sessions INTEGER,      -- NULL = inherit global; 0 = unlimited
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
