# Fleet Terminal — Database Schema Reference

The schema is normalized PostgreSQL covering identity, RBAC, hosts, certificates,
sessions, recordings, approvals, enrollment, and a tamper-evident audit log. It is
defined by the migrations in `backend/internal/db/migrations/` and applied
automatically on startup when `FLEET_MIGRATE_ON_START=true` (the default).

| Migration | Purpose |
|-----------|---------|
| `0001_init.sql` | Core schema (all tables below) |
| `0002_seed_rbac.sql` | Permission catalog, built-in roles, default settings |
| `0003_cert_serial.sql` | `ssh_cert_serial_seq` monotonic certificate serial sequence |
| `0004_host_address_text.sql` | Host management address stored as text |
| `0005_host_users.sql` | Direct user→host access grants (`host_users`) |
| `0006_require_mfa.sql` | `require_mfa` system setting |
| `0007_host_sudo.sql` | `Host.Sudo` permission (root vs login-only host access) |
| `0008_branding.sql` | `branding` system setting (customizable app name) |
| `0009_host_scans.sql` | `host_scans` table + `Host.Scan` permission (OpenSCAP scans) |
| `0010_host_metrics.sql` | `host_metrics` table (disk/memory/load/network per host) |
| `0011_assistant.sql` | `Assistant.Use` permission + `assistant` setting (AI assistant) |
| `0010_host_remediation.sql` | `host_remediations` table + `Host.Remediate` permission; `host_scans.results_path` |
| `0011_scan_skip_rules.sql` | `host_scans.skip_rules` (rules excluded from a scan) |

**Extensions:** `pgcrypto` (`gen_random_uuid()`), `citext` (case-insensitive
usernames/emails).

Conventions: primary keys are `UUID DEFAULT gen_random_uuid()` unless noted;
timestamps are `TIMESTAMPTZ`; `created_at`/`updated_at` default to `now()`.

---

## Identity & authentication

### `users`
The principal record. Password material is deliberately kept out of this row.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `username` | CITEXT | UNIQUE, case-insensitive |
| `email` | CITEXT | UNIQUE, nullable |
| `display_name` | TEXT | default `''` |
| `is_super_admin` | BOOLEAN | bypasses RBAC; treated as `Admin.All` |
| `is_disabled` | BOOLEAN | disabled accounts cannot log in |
| `email_verified` | BOOLEAN | |
| `must_change_pw` | BOOLEAN | forces password change at next login |
| `failed_logins` | INT | drives lockout |
| `locked_until` | TIMESTAMPTZ | nullable; lockout expiry |
| `last_login_at` | TIMESTAMPTZ | nullable |
| `created_at` / `updated_at` | TIMESTAMPTZ | |

### `user_credentials`
Password material isolated for least-privilege reads. 1:1 with `users`.

| Column | Type | Notes |
|--------|------|-------|
| `user_id` | UUID PK | FK → users ON DELETE CASCADE |
| `password_hash` | TEXT | Argon2id encoded string |
| `pw_changed_at` | TIMESTAMPTZ | |
| `pw_history` | JSONB | array of recent hashes (no-reuse policy) |

### `mfa_methods`
Enrolled second factors. Index: `idx_mfa_user(user_id)`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `user_id` | UUID | FK → users CASCADE |
| `kind` | TEXT | CHECK in (`totp`,`webauthn`) |
| `label` | TEXT | |
| `secret` | BYTEA | encrypted TOTP secret or WebAuthn blob |
| `confirmed` | BOOLEAN | |
| `created_at` / `last_used_at` | TIMESTAMPTZ | |

### `auth_events`
Login/security events, separate from the audit chain for fast queries.
Indexes: `idx_auth_events_user`, `idx_auth_events_created(created_at DESC)`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | BIGINT identity PK | |
| `user_id` | UUID | FK → users ON DELETE SET NULL |
| `username` | CITEXT | |
| `event` | TEXT | `login_success`, `login_failure`, `logout`, `lockout`, `mfa_*`, `pw_change` |
| `ip` | INET | |
| `user_agent` | TEXT | |
| `detail` | JSONB | default `{}` |
| `created_at` | TIMESTAMPTZ | |

### `sessions`
Browser sessions. Each session owns an ephemeral SSH identity held only in RAM;
only certificate metadata is persisted (in `ssh_certificates`).
Indexes: `idx_sessions_user`, `idx_sessions_expires`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `user_id` | UUID | FK → users CASCADE |
| `refresh_hash` | TEXT | hash of current (rotating) refresh token |
| `ip` | INET | |
| `user_agent` | TEXT | |
| `mfa_passed` | BOOLEAN | |
| `created_at` / `last_seen_at` | TIMESTAMPTZ | |
| `expires_at` | TIMESTAMPTZ | |
| `revoked_at` | TIMESTAMPTZ | nullable |

---

## RBAC

### `roles`
| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `name` | TEXT | UNIQUE |
| `description` | TEXT | |
| `is_builtin` | BOOLEAN | built-in roles cannot be deleted |
| `created_at` | TIMESTAMPTZ | |

Seeded built-in roles: **Super Administrator**, **Administrator**, **Operator**,
**Auditor**, **Read-Only**.

### `permissions`
| Column | Type | Notes |
|--------|------|-------|
| `key` | TEXT PK | e.g. `Host.Connect` |
| `description` | TEXT | |

Seeded keys: `Host.View`, `Host.Connect`, `Host.Sudo`, `Host.Enroll`, `Host.Edit`,
`Host.Delete`, `Host.RotateCertificate`, `Session.Start`, `Session.Terminate`,
`Session.Replay`, `File.Transfer`, `Audit.View`, `Audit.Export`, `User.Create`,
`User.Edit`, `User.Delete`, `User.ResetPassword`, `Group.Create`, `Group.Edit`,
`Group.Delete`, `Role.Create`, `Role.Edit`, `Role.Delete`, `Approval.Request`,
`Approval.Decide`, `Certificate.Manage`, `System.Configure`, `Host.Scan`,
`Assistant.Use`, `Host.Remediate`, `Admin.All` (wildcard).

### `role_permissions`
Join table. PK `(role_id, permission_key)`; both FKs CASCADE.

### `user_roles`
Join table. PK `(user_id, role_id)`; both FKs CASCADE.

---

## Groups

Group membership grants host authorization: a user can reach a host when they
share a group with it (or hold an active temporary grant).

### `groups`
| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `name` | TEXT | UNIQUE |
| `description` | TEXT | |
| `created_at` | TIMESTAMPTZ | |

### `user_groups`
Join table. PK `(user_id, group_id)`; both FKs CASCADE.

---

## Hosts & inventory

### `hosts`
Indexes: `idx_hosts_env(environment)`, `idx_hosts_tags` (GIN on `tags`).

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `hostname` | TEXT | UNIQUE |
| `description` | TEXT | |
| `environment` | TEXT | default `production` |
| `owner` | TEXT | |
| `address` | INET | routable mgmt address (from jump host) |
| `wg_address` | INET | WireGuard tunnel address |
| `ssh_port` | INT | default 22 |
| `ssh_user` | TEXT | default `fleet` |
| `tags` | TEXT[] | default `{}` |
| `enrolled` | BOOLEAN | set once enrollment succeeds |
| `created_at` / `updated_at` | TIMESTAMPTZ | |

### `host_groups`
Join table host↔group. PK `(host_id, group_id)`; both FKs CASCADE.

### `host_inventory`
Collected facts, 1:1 with host.

| Column | Type | Notes |
|--------|------|-------|
| `host_id` | UUID PK | FK → hosts CASCADE |
| `os_name` / `os_version` / `kernel_version` / `architecture` / `ssh_version` | TEXT | |
| `cpu_count` | INT | |
| `memory_mb` | BIGINT | |
| `collected_at` | TIMESTAMPTZ | nullable |

### `host_fingerprints`
Known SSH host keys. UNIQUE `(host_id, key_type)`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `host_id` | UUID | FK → hosts CASCADE |
| `key_type` | TEXT | `ssh-ed25519`, `ecdsa`, `rsa` |
| `fingerprint` | TEXT | `SHA256:…` |
| `created_at` | TIMESTAMPTZ | |

### `host_status`
Live status, 1:1 with host, updated by the monitor.

| Column | Type | Notes |
|--------|------|-------|
| `host_id` | UUID PK | FK → hosts CASCADE |
| `status` | TEXT | CHECK in (`online`,`offline`,`unknown`) |
| `ssh_ok` / `wg_ok` | BOOLEAN | |
| `latency_ms` | INT | nullable |
| `uptime_seconds` | BIGINT | nullable |
| `last_success_at` / `last_failure_at` / `checked_at` | TIMESTAMPTZ | nullable |
| `last_error` | TEXT | |

---

## SSH Certificate Authority

### `ca_keys`
CA signing keys. The private key is encrypted at rest and never leaves the
backend. Index: `idx_ca_keys_active(kind, active)`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `kind` | TEXT | CHECK in (`user`,`host`) |
| `algo` | TEXT | default `ssh-ed25519` |
| `public_key` | TEXT | authorized_keys form |
| `private_enc` | BYTEA | encrypted private key (`FLEET_CA_PASSPHRASE`) |
| `fingerprint` | TEXT | |
| `active` | BOOLEAN | |
| `created_at` / `retired_at` | TIMESTAMPTZ | |

### `ssh_certificates`
Metadata of every issued certificate. **Private keys are NEVER stored.**
Indexes: `idx_certs_session`, `idx_certs_user`, `idx_certs_expires`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `serial` | BIGINT | UNIQUE; from `ssh_cert_serial_seq` |
| `kind` | TEXT | CHECK in (`user`,`host`) |
| `ca_key_id` | UUID | FK → ca_keys |
| `user_id` | UUID | FK → users ON DELETE SET NULL |
| `session_id` | UUID | FK → sessions CASCADE |
| `host_id` | UUID | FK → hosts CASCADE |
| `key_id` | TEXT | OpenSSH cert key id (audit handle) |
| `principals` | TEXT[] | |
| `public_key` | TEXT | |
| `audit_id` | UUID | links to the issuing audit event |
| `issued_at` / `expires_at` / `revoked_at` | TIMESTAMPTZ | |
| `revoke_reason` | TEXT | |

### `cert_revocations`
The revocation list source (exposed as a KRL).

| Column | Type | Notes |
|--------|------|-------|
| `serial` | BIGINT PK | |
| `reason` | TEXT | |
| `revoked_at` | TIMESTAMPTZ | |

---

## SSH sessions & recordings

### `ssh_sessions`
One row per terminal session. Indexes: `idx_ssh_sessions_user`,
`idx_ssh_sessions_host`, `idx_ssh_sessions_started(started_at DESC)`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `session_id` | UUID | FK → sessions ON DELETE SET NULL (browser session) |
| `user_id` | UUID | FK → users ON DELETE SET NULL |
| `host_id` | UUID | FK → hosts ON DELETE SET NULL |
| `username` | CITEXT | |
| `hostname` | TEXT | |
| `cert_serial` | BIGINT | certificate used |
| `status` | TEXT | CHECK in (`active`,`closed`,`error`) |
| `started_at` / `ended_at` | TIMESTAMPTZ | |
| `exit_code` | INT | nullable |
| `bytes_in` / `bytes_out` | BIGINT | |
| `client_ip` | INET | |

### `session_recordings`
asciicast recordings. Index: `idx_recordings_session`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `ssh_session_id` | UUID | FK → ssh_sessions CASCADE |
| `format` | TEXT | default `asciicast-v2` |
| `path` | TEXT | on-disk/object-store location (relative paths resolve under `FLEET_RECORDING_DIR`) |
| `size_bytes` | BIGINT | |
| `duration_ms` | BIGINT | |
| `sha256` | TEXT | integrity hash |
| `created_at` | TIMESTAMPTZ | |

### `sftp_transfers`
File transfer audit records.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `ssh_session_id` | UUID | FK → ssh_sessions ON DELETE SET NULL |
| `user_id` | UUID | FK → users ON DELETE SET NULL |
| `host_id` | UUID | FK → hosts ON DELETE SET NULL |
| `direction` | TEXT | CHECK in (`upload`,`download`) |
| `remote_path` | TEXT | |
| `size_bytes` | BIGINT | |
| `status` | TEXT | CHECK in (`started`,`completed`,`failed`) |
| `created_at` / `completed_at` | TIMESTAMPTZ | |

---

## Just-in-time approvals

### `approval_requests`
Indexes: `idx_approvals_status`, `idx_approvals_requester`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `requester_id` | UUID | FK → users CASCADE |
| `target_kind` | TEXT | CHECK in (`host`,`group`) |
| `host_id` | UUID | FK → hosts CASCADE (nullable) |
| `group_id` | UUID | FK → groups CASCADE (nullable) |
| `reason` | TEXT | |
| `ticket_ref` | TEXT | |
| `requested_secs` | BIGINT | requested duration |
| `status` | TEXT | CHECK in (`pending`,`approved`,`denied`,`expired`,`cancelled`) |
| `decided_by` | UUID | FK → users ON DELETE SET NULL |
| `decided_at` | TIMESTAMPTZ | |
| `decision_note` | TEXT | |
| `granted_secs` | BIGINT | actual granted duration |
| `created_at` | TIMESTAMPTZ | |

### `temporary_permissions`
Time-boxed grants minted by approvals. Indexes: `idx_temp_perms_user`,
`idx_temp_perms_expires`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `request_id` | UUID | FK → approval_requests CASCADE |
| `user_id` | UUID | FK → users CASCADE |
| `host_id` | UUID | FK → hosts CASCADE (nullable) |
| `group_id` | UUID | FK → groups CASCADE (nullable) |
| `granted_at` / `expires_at` / `revoked_at` | TIMESTAMPTZ | |

---

## Host enrollment

### `enrollment_jobs`
Tracks enrollment runs and their step log. Index: `idx_enrollment_status`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `host_id` | UUID | FK → hosts CASCADE |
| `target` | TEXT | `address:port` being enrolled |
| `os_hint` | TEXT | |
| `status` | TEXT | CHECK in (`pending`,`running`,`succeeded`,`failed`,`rolled_back`) |
| `steps` | JSONB | ordered step log |
| `error` | TEXT | |
| `created_by` | UUID | FK → users ON DELETE SET NULL |
| `created_at` / `started_at` / `finished_at` | TIMESTAMPTZ | |

---

## Tamper-evident audit log

### `audit_events`
Hash-chained: `hash = H(prev_hash || canonical(event))`. Verified via
`GET /api/v1/audit/verify`. Indexes: `idx_audit_action`, `idx_audit_actor`,
`idx_audit_created(created_at DESC)`.

| Column | Type | Notes |
|--------|------|-------|
| `seq` | BIGINT identity PK | monotonic chain order |
| `id` | UUID | event id |
| `actor_id` | UUID | FK → users ON DELETE SET NULL |
| `actor_name` | CITEXT | denormalized for retention after user deletion |
| `action` | TEXT | e.g. `session.start`, `user.delete` |
| `target_kind` / `target_id` | TEXT | |
| `ip` | INET | |
| `detail` | JSONB | default `{}` |
| `prev_hash` | TEXT | hash of previous row |
| `hash` | TEXT | this row's chain hash |
| `created_at` | TIMESTAMPTZ | |

---

## Dashboards & settings

### `saved_filters`
Per-user saved queries. UNIQUE `(user_id, scope, name)`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `user_id` | UUID | FK → users CASCADE |
| `name` | TEXT | |
| `scope` | TEXT | default `hosts` |
| `query` | JSONB | |
| `created_at` | TIMESTAMPTZ | |

### `settings`
Key/value system settings.

| Column | Type | Notes |
|--------|------|-------|
| `key` | TEXT PK | |
| `value` | JSONB | |
| `updated_at` | TIMESTAMPTZ | |

Seeded keys: `password_policy`, `lockout_policy`, `session_policy`, `require_mfa`,
`branding`, `assistant`.

---

## Sequences

- `ssh_cert_serial_seq` — `BIGINT START WITH 1 INCREMENT BY 1`. Source of unique,
  never-reused certificate serials for revocation (KRL) and audit.
