-- Track the last accepted TOTP timestep per user so a code can't be replayed
-- within the validation skew window. Additive and nullable-by-default (0 = none
-- used yet), so existing users are unaffected and login is never blocked by it.
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_totp_step BIGINT NOT NULL DEFAULT 0;
