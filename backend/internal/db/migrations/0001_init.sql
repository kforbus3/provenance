-- Provenance core schema.
-- Normalized PostgreSQL schema covering identity, RBAC, hosts, certificates,
-- sessions, recordings, approvals, enrollment, and tamper-evident audit.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "citext";     -- case-insensitive emails/usernames

-- ---------------------------------------------------------------------------
-- Identity & authentication
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        CITEXT NOT NULL UNIQUE,
    email           CITEXT UNIQUE,
    display_name    TEXT NOT NULL DEFAULT '',
    is_super_admin  BOOLEAN NOT NULL DEFAULT false,
    is_disabled     BOOLEAN NOT NULL DEFAULT false,
    email_verified  BOOLEAN NOT NULL DEFAULT false,
    must_change_pw  BOOLEAN NOT NULL DEFAULT false,
    failed_logins   INT NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Password material is isolated from the user row (least privilege on reads).
CREATE TABLE user_credentials (
    user_id        UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash  TEXT NOT NULL,            -- Argon2id encoded string
    pw_changed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- history of recent hashes to enforce no-reuse policy (JSON array of strings)
    pw_history     JSONB NOT NULL DEFAULT '[]'
);

CREATE TABLE mfa_methods (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('totp','webauthn')),
    label       TEXT NOT NULL DEFAULT '',
    secret      BYTEA,                       -- TOTP secret (encrypted) or WebAuthn credential blob
    confirmed   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);
CREATE INDEX idx_mfa_user ON mfa_methods(user_id);

-- Login/security events (separate from the general audit chain for fast queries).
CREATE TABLE auth_events (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    username    CITEXT,
    event       TEXT NOT NULL,              -- login_success, login_failure, logout, lockout, mfa_*, pw_change
    ip          INET,
    user_agent  TEXT,
    detail      JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_auth_events_user ON auth_events(user_id);
CREATE INDEX idx_auth_events_created ON auth_events(created_at DESC);

-- Browser sessions. A session owns an ephemeral SSH identity (kept only in RAM;
-- only the certificate metadata is persisted in ssh_certificates).
CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_hash    TEXT NOT NULL,           -- hash of current refresh token (rotating)
    ip              INET,
    user_agent      TEXT,
    mfa_passed      BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

-- ---------------------------------------------------------------------------
-- RBAC: roles, permissions
-- ---------------------------------------------------------------------------
CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    is_builtin  BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE permissions (
    key         TEXT PRIMARY KEY,            -- e.g. 'Host.Connect'
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE role_permissions (
    role_id        UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_key TEXT NOT NULL REFERENCES permissions(key) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_key)
);

CREATE TABLE user_roles (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- ---------------------------------------------------------------------------
-- Groups: users<->groups and hosts<->groups grant host authorization
-- ---------------------------------------------------------------------------
CREATE TABLE groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_groups (
    user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

-- ---------------------------------------------------------------------------
-- Hosts & inventory
-- ---------------------------------------------------------------------------
CREATE TABLE hosts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname      TEXT NOT NULL UNIQUE,
    description   TEXT NOT NULL DEFAULT '',
    environment   TEXT NOT NULL DEFAULT 'production',
    owner         TEXT NOT NULL DEFAULT '',
    address       INET,                       -- routable mgmt address (from jump host)
    wg_address    INET,                       -- WireGuard tunnel address
    ssh_port      INT NOT NULL DEFAULT 22,
    ssh_user      TEXT NOT NULL DEFAULT 'fleet',
    tags          TEXT[] NOT NULL DEFAULT '{}',
    enrolled      BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_hosts_env ON hosts(environment);
CREATE INDEX idx_hosts_tags ON hosts USING GIN(tags);

CREATE TABLE host_groups (
    host_id  UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (host_id, group_id)
);

-- Collected facts (1:1 with host, refreshed by enrollment/monitoring).
CREATE TABLE host_inventory (
    host_id        UUID PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    os_name        TEXT NOT NULL DEFAULT '',
    os_version     TEXT NOT NULL DEFAULT '',
    kernel_version TEXT NOT NULL DEFAULT '',
    architecture   TEXT NOT NULL DEFAULT '',
    ssh_version    TEXT NOT NULL DEFAULT '',
    cpu_count      INT NOT NULL DEFAULT 0,
    memory_mb      BIGINT NOT NULL DEFAULT 0,
    collected_at   TIMESTAMPTZ
);

CREATE TABLE host_fingerprints (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    key_type    TEXT NOT NULL,               -- ssh-ed25519, ecdsa, rsa
    fingerprint TEXT NOT NULL,               -- SHA256:...
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (host_id, key_type)
);

-- Live status (1:1), updated by the monitor and pushed over WebSocket.
CREATE TABLE host_status (
    host_id          UUID PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    status           TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('online','offline','unknown')),
    ssh_ok           BOOLEAN NOT NULL DEFAULT false,
    wg_ok            BOOLEAN NOT NULL DEFAULT false,
    latency_ms       INT,
    uptime_seconds   BIGINT,
    last_success_at  TIMESTAMPTZ,
    last_failure_at  TIMESTAMPTZ,
    last_error       TEXT NOT NULL DEFAULT '',
    checked_at       TIMESTAMPTZ
);

-- ---------------------------------------------------------------------------
-- SSH Certificate Authority & issued certificates
-- ---------------------------------------------------------------------------
CREATE TABLE ca_keys (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind          TEXT NOT NULL CHECK (kind IN ('user','host')),
    algo          TEXT NOT NULL DEFAULT 'ssh-ed25519',
    public_key    TEXT NOT NULL,             -- authorized_keys form
    private_enc   BYTEA NOT NULL,            -- encrypted private key (never leaves backend)
    fingerprint   TEXT NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at    TIMESTAMPTZ
);
CREATE INDEX idx_ca_keys_active ON ca_keys(kind, active);

-- Metadata of every issued user/host certificate. Private keys are NEVER stored.
CREATE TABLE ssh_certificates (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial        BIGINT NOT NULL UNIQUE,
    kind          TEXT NOT NULL CHECK (kind IN ('user','host')),
    ca_key_id     UUID NOT NULL REFERENCES ca_keys(id),
    user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    session_id    UUID REFERENCES sessions(id) ON DELETE CASCADE,
    host_id       UUID REFERENCES hosts(id) ON DELETE CASCADE,
    key_id        TEXT NOT NULL,             -- OpenSSH cert key id (audit handle)
    principals    TEXT[] NOT NULL DEFAULT '{}',
    public_key    TEXT NOT NULL,
    audit_id      UUID NOT NULL,
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ,
    revoke_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_certs_session ON ssh_certificates(session_id);
CREATE INDEX idx_certs_user ON ssh_certificates(user_id);
CREATE INDEX idx_certs_expires ON ssh_certificates(expires_at);

CREATE TABLE cert_revocations (
    serial      BIGINT PRIMARY KEY,
    reason      TEXT NOT NULL DEFAULT '',
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- SSH sessions & recordings
-- ---------------------------------------------------------------------------
CREATE TABLE ssh_sessions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id    UUID REFERENCES sessions(id) ON DELETE SET NULL,
    user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    host_id       UUID REFERENCES hosts(id) ON DELETE SET NULL,
    username      CITEXT,
    hostname      TEXT,
    cert_serial   BIGINT,
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','closed','error')),
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at      TIMESTAMPTZ,
    exit_code     INT,
    bytes_in      BIGINT NOT NULL DEFAULT 0,
    bytes_out     BIGINT NOT NULL DEFAULT 0,
    client_ip     INET
);
CREATE INDEX idx_ssh_sessions_user ON ssh_sessions(user_id);
CREATE INDEX idx_ssh_sessions_host ON ssh_sessions(host_id);
CREATE INDEX idx_ssh_sessions_started ON ssh_sessions(started_at DESC);

CREATE TABLE session_recordings (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ssh_session_id UUID NOT NULL REFERENCES ssh_sessions(id) ON DELETE CASCADE,
    format         TEXT NOT NULL DEFAULT 'asciicast-v2',
    path           TEXT NOT NULL,            -- on-disk/object-store location
    size_bytes     BIGINT NOT NULL DEFAULT 0,
    duration_ms    BIGINT NOT NULL DEFAULT 0,
    sha256         TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_recordings_session ON session_recordings(ssh_session_id);

CREATE TABLE sftp_transfers (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ssh_session_id UUID REFERENCES ssh_sessions(id) ON DELETE SET NULL,
    user_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    host_id        UUID REFERENCES hosts(id) ON DELETE SET NULL,
    direction      TEXT NOT NULL CHECK (direction IN ('upload','download')),
    remote_path    TEXT NOT NULL,
    size_bytes     BIGINT NOT NULL DEFAULT 0,
    status         TEXT NOT NULL DEFAULT 'started' CHECK (status IN ('started','completed','failed')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at   TIMESTAMPTZ
);

-- ---------------------------------------------------------------------------
-- Just-in-time approval workflow
-- ---------------------------------------------------------------------------
CREATE TABLE approval_requests (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_kind    TEXT NOT NULL CHECK (target_kind IN ('host','group')),
    host_id        UUID REFERENCES hosts(id) ON DELETE CASCADE,
    group_id       UUID REFERENCES groups(id) ON DELETE CASCADE,
    reason         TEXT NOT NULL DEFAULT '',
    ticket_ref     TEXT NOT NULL DEFAULT '',
    requested_secs BIGINT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','approved','denied','expired','cancelled')),
    decided_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    decided_at     TIMESTAMPTZ,
    decision_note  TEXT NOT NULL DEFAULT '',
    granted_secs   BIGINT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_approvals_status ON approval_requests(status);
CREATE INDEX idx_approvals_requester ON approval_requests(requester_id);

CREATE TABLE temporary_permissions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id   UUID REFERENCES approval_requests(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    host_id      UUID REFERENCES hosts(id) ON DELETE CASCADE,
    group_id     UUID REFERENCES groups(id) ON DELETE CASCADE,
    granted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX idx_temp_perms_user ON temporary_permissions(user_id);
CREATE INDEX idx_temp_perms_expires ON temporary_permissions(expires_at);

-- ---------------------------------------------------------------------------
-- Host enrollment jobs
-- ---------------------------------------------------------------------------
CREATE TABLE enrollment_jobs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id      UUID REFERENCES hosts(id) ON DELETE CASCADE,
    target       TEXT NOT NULL,              -- address:port being enrolled
    os_hint      TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','running','succeeded','failed','rolled_back')),
    steps        JSONB NOT NULL DEFAULT '[]',-- ordered step log
    error        TEXT NOT NULL DEFAULT '',
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ
);
CREATE INDEX idx_enrollment_status ON enrollment_jobs(status);

-- ---------------------------------------------------------------------------
-- Tamper-evident audit log (hash-chained)
-- ---------------------------------------------------------------------------
CREATE TABLE audit_events (
    seq         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id          UUID NOT NULL DEFAULT gen_random_uuid(),
    actor_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_name  CITEXT,
    action      TEXT NOT NULL,               -- e.g. 'session.start', 'user.delete'
    target_kind TEXT NOT NULL DEFAULT '',
    target_id   TEXT NOT NULL DEFAULT '',
    ip          INET,
    detail      JSONB NOT NULL DEFAULT '{}',
    prev_hash   TEXT NOT NULL DEFAULT '',
    hash        TEXT NOT NULL,               -- H(prev_hash || canonical(event))
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_action ON audit_events(action);
CREATE INDEX idx_audit_actor ON audit_events(actor_id);
CREATE INDEX idx_audit_created ON audit_events(created_at DESC);

-- ---------------------------------------------------------------------------
-- Saved dashboard filters & system settings
-- ---------------------------------------------------------------------------
CREATE TABLE saved_filters (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    scope      TEXT NOT NULL DEFAULT 'hosts',
    query      JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, scope, name)
);

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
