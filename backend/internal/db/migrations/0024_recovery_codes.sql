-- MFA recovery codes: single-use backup codes that stand in for TOTP/WebAuthn
-- when a user loses their authenticator, so the strongest (admin) accounts aren't
-- lost on a lost phone. Codes are high-entropy and stored only as SHA-256 hashes
-- (they are verified by match and marked used — never decrypted), the same
-- treatment as API tokens and refresh tokens.

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    used_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user ON mfa_recovery_codes(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mfa_recovery_hash ON mfa_recovery_codes(code_hash);
