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
| `0012_playbooks.sql` | `playbooks`, `playbook_versions`, `playbook_runs` tables + `Playbook.Edit`/`Playbook.Run` permissions (Ansible playbook management) |
| `0013_schedules.sql` | `schedules` table + `Schedule.Manage` permission (recurring scans/playbook runs) |
| `0014_host_updates.sql` | `host_inventory.updates_available`, `.security_updates`, `.updates_checked_at` (pending package updates per host) |
| `0015_scheduled_flag.sql` | `scheduled` flag on `host_scans` and `playbook_runs` (distinguish scheduled from manual runs) |
| `0016_external_auth.sql` | `users.auth_source` (external identity providers: OIDC SSO / LDAP) |
| `0017_totp_last_step.sql` | TOTP replay guard (records last-used timestep per user) |
| `0018_host_access_denials.sql` | Explicit per-user host access denials (override grants) |
| `0019_operator_no_replay.sql` | Remove `Session.Replay` from the built-in Operator role |
| `0020_schedule_run_ids.sql` | Track scan/run ids a schedule fire launched |
| `0021_host_metrics_history.sql` | `host_metrics_history` append-only host metric time series (trends) |
| `0022_service_accounts.sql` | `users.is_service_account` + `api_tokens` table + `ServiceAccount.Manage` permission |
| `0023_session_watch.sql` | `Session.Watch` permission (live session shadowing) |
| `0024_recovery_codes.sql` | `mfa_recovery_codes` table (hashed one-time MFA backup codes) |
| `0025_group_rules.sql` | `groups.rule` (JSONB) for dynamic group membership |
| `0026_vuln_scans.sql` | `vuln_scans` + `vuln_findings` tables (Grype CVE scanning) |

> **Duplicate numeric prefixes are intentional, not a bug.** There are two
> `0010_*` and two `0011_*` files. The runner (`backend/internal/db/migrate.go`)
> sorts files lexically and keys applied migrations in `schema_migrations` by the
> full filename (e.g. `0010_host_metrics`, `0010_host_remediation`), not by the
> numeric prefix — so each file is applied exactly once and the collisions are
> harmless.

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
| `auth_source` | TEXT | `local` \| `oidc` \| `ldap`; default `local` (added in `0016`). External (`oidc`/`ldap`) accounts are provisioned on first SSO/directory login and have no usable local password |
| `is_service_account` | BOOLEAN | default `false` (added in `0022`). Flags a non-human identity: no password, cannot log in interactively or via SSO; authenticates the REST API through an `api_tokens` bearer |
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

### `mfa_recovery_codes`
One-time MFA backup codes (added in `0024`). Ten are generated at once and stored
only as SHA-256 hashes (never decrypted); generating a new set invalidates the old
one. A code is consumed via the normal MFA verify path.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `user_id` | UUID | FK → users CASCADE |
| `code_hash` | TEXT | SHA-256 of the `xxxx-xxxx-xxxx` code |
| `used_at` | TIMESTAMPTZ | nullable; set when consumed |
| `created_at` | TIMESTAMPTZ | |

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

### `api_tokens`
Service-account API tokens (added in `0022`). The `flt_<random>` plaintext is
shown once at creation and stored only as a SHA-256 hash; the token authenticates
the REST API as `Authorization: Bearer flt_...`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `service_account_id` | UUID | FK → users CASCADE (a `users` row with `is_service_account = true`) |
| `name` | TEXT | operator-facing label |
| `token_hash` | TEXT | SHA-256 of the plaintext token |
| `prefix` | TEXT | `flt_…` display prefix (never the full secret) |
| `created_by` | UUID | FK → users ON DELETE SET NULL |
| `expires_at` | TIMESTAMPTZ | nullable; `NULL` = never expires |
| `last_used_at` | TIMESTAMPTZ | nullable; updated on use (throttled to ~1/min) |
| `revoked_at` | TIMESTAMPTZ | nullable |
| `created_at` | TIMESTAMPTZ | |

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
`Assistant.Use`, `Host.Remediate`, `Playbook.Edit`, `Playbook.Run`,
`Schedule.Manage`, `ServiceAccount.Manage`, `Session.Watch`, `Admin.All`
(wildcard).

`Playbook.Edit` (author/edit/validate/lint playbooks), `Playbook.Run` (execute
playbooks against hosts), and `Schedule.Manage` (manage scheduled scans/playbook
runs) are added by migrations `0012`/`0013` and granted to **Administrator** by
default.

`ServiceAccount.Manage` (manage service accounts and their API tokens) is added by
migration `0022` and seeded to **Super Administrator** + **Administrator**.
`Session.Watch` (live-shadow an active terminal session) is added by migration
`0023` and seeded to **Super Administrator**, **Administrator**, and **Auditor**.

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
| `rule` | JSONB | nullable (added in `0025`). A **dynamic-group** rule over stable host attributes — `environment` (exact), `tagsAll`, `tagsAny`, `osContains`, `hostnameContains`. Matching hosts are materialized into `host_groups`, recomputed on save and by a reconcile loop; `NULL`/empty = a static/manual group. Manual host add/remove is refused on a rule-managed group |
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
| `updates_available` | INT | nullable; pending package updates (NULL = not yet checked, distinct from `0`) |
| `security_updates` | INT | nullable; pending security updates |
| `updates_checked_at` | TIMESTAMPTZ | nullable; when update counts were last collected |
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

### `host_metrics_history`
Append-only time series of host metrics (added in `0021`), sampled every
`FLEET_METRIC_HISTORY_SAMPLE` (5m) and retained `FLEET_METRIC_HISTORY_RETENTION`
(720h). Powers trend analysis, the disk-runway projection, and the insights
engine. Index on `(host_id, collected_at DESC)`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | BIGINT identity PK | |
| `host_id` | UUID | FK → hosts CASCADE |
| `disk_pct` / `memory_pct` / `load1` | DOUBLE PRECISION | sampled utilization/load |
| `collected_at` | TIMESTAMPTZ | sample time |

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

## Playbooks & scheduling

Ansible playbooks authored in the UI, their version history, individual run
records, and the recurring-schedule definitions that drive automated scans and
playbook runs.

### `playbooks`
A single YAML document plus metadata. `version` is bumped on each content change;
the prior content is snapshotted into `playbook_versions`.
Index: `idx_playbooks_name` (on `lower(name)`).

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `name` | TEXT | NOT NULL |
| `description` | TEXT | default `''` |
| `content` | TEXT | default `''`; the playbook YAML |
| `version` | INT | default `1`; bumped on each content change |
| `created_by` | UUID | FK → users ON DELETE SET NULL |
| `updated_by` | UUID | FK → users ON DELETE SET NULL |
| `created_at` / `updated_at` | TIMESTAMPTZ | |

### `playbook_versions`
Immutable revision history: one row per saved revision so edits are auditable and
recoverable. UNIQUE `(playbook_id, version)`. Index: `idx_playbook_versions_pb`
(`playbook_id, version DESC`).

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `playbook_id` | UUID | FK → playbooks ON DELETE CASCADE |
| `version` | INT | NOT NULL |
| `content` | TEXT | default `''` |
| `author_id` | UUID | FK → users ON DELETE SET NULL |
| `author` | TEXT | denormalized author name, default `''` |
| `created_at` | TIMESTAMPTZ | |

### `playbook_runs`
One execution of a playbook against a target (a single host or a Fleet group).
`output` holds the captured log. Indexes: `idx_playbook_runs_pb`
(`playbook_id, created_at DESC`), `idx_playbook_runs_status`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `playbook_id` | UUID | FK → playbooks ON DELETE CASCADE |
| `playbook_version` | INT | default `0`; version run |
| `requested_by` | UUID | FK → users ON DELETE SET NULL |
| `requester` | TEXT | denormalized requester name, default `''` |
| `target_kind` | TEXT | `host` or `group`, default `host` |
| `target_id` | UUID | host id or group id (nullable) |
| `target_name` | TEXT | display name, default `''` |
| `host_count` | INT | number of targeted hosts, default `0` |
| `check_mode` | BOOLEAN | `ansible --check` (dry run), default `false` |
| `status` | TEXT | `pending`/`running`/`completed`/`failed`, default `pending` |
| `exit_code` | INT | nullable |
| `output` | TEXT | captured log, default `''` |
| `error` | TEXT | default `''` |
| `scheduled` | BOOLEAN | default `false`; set when fired by a schedule (added in `0015`) |
| `started_at` / `finished_at` | TIMESTAMPTZ | nullable |
| `created_at` | TIMESTAMPTZ | |

> `host_scans` likewise gains a `scheduled BOOLEAN NOT NULL DEFAULT false` column
> (migration `0015`) so scheduled scans can be filtered/reported separately from
> manual ones.

### `schedules`
Recurring scans and playbook runs configured in the UI. Schedules are **disabled
by default**; an operator enables one explicitly. A background engine fires due,
enabled schedules by reusing the normal scan/playbook run paths.
Index: `idx_schedules_due` (on `next_run_at`, partial `WHERE enabled`).

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `name` | TEXT | NOT NULL |
| `kind` | TEXT | `scan` or `playbook` |
| `enabled` | BOOLEAN | default `false` |
| `target_kind` | TEXT | `host` or `group`, default `host` |
| `target_id` | UUID | host id or group id (nullable) |
| `target_name` | TEXT | default `''` |
| `recurrence` | JSONB | default `{}`; `{type, everyMinutes, timeOfDay, weekday}` |
| `payload` | JSONB | default `{}`; scan or playbook parameters |
| `created_by` | UUID | FK → users ON DELETE SET NULL |
| `requester` | TEXT | default `''` |
| `last_run_at` | TIMESTAMPTZ | nullable |
| `last_status` | TEXT | default `''` |
| `next_run_at` | TIMESTAMPTZ | nullable; `NULL` when disabled |
| `created_at` / `updated_at` | TIMESTAMPTZ | |

---

## Vulnerability scans

CVE scanning (added in `0026`), distinct from OpenSCAP compliance: a host's
installed packages are matched against a Grype CVE database and findings are
recorded with CVSS scores.

### `vuln_scans`
One CVE scan of a host. A completed row carries the per-severity roll-up and the
maximum CVSS observed. Index on `(host_id, created_at DESC)`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `host_id` | UUID | FK → hosts CASCADE |
| `status` | TEXT | `pending`/`running`/`completed`/`failed` |
| `scheduled` | BOOLEAN | default `false`; set when fired by a `vulnscan` schedule |
| `critical_count` / `high_count` / `medium_count` / `low_count` | INT | per-severity finding counts |
| `max_cvss` | DOUBLE PRECISION | nullable; highest CVSS across findings |
| `error` | TEXT | default `''` |
| `requested_by` | UUID | FK → users ON DELETE SET NULL |
| `started_at` / `finished_at` | TIMESTAMPTZ | nullable |
| `created_at` | TIMESTAMPTZ | |

### `vuln_findings`
One CVE finding within a scan. Index on `vuln_scan_id`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `vuln_scan_id` | UUID | FK → vuln_scans CASCADE |
| `cve_id` | TEXT | CVE identifier |
| `package` | TEXT | affected package |
| `installed_version` / `fixed_version` | TEXT | installed vs. fixing version (fixed nullable/empty if none) |
| `severity` | TEXT | Grype severity |
| `cvss_score` | DOUBLE PRECISION | nullable; enriched from related NVD records when the distro source lacks a score |
| `cvss_vector` | TEXT | |
| `data_source` | TEXT | vulnerability data source |
| `description` | TEXT | |

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

Additional keys written on first use (not part of the `0002` seed):
`notifications` (notification channels/events), `backup_policy` (automatic
database-backup schedule), `timezone` (IANA display timezone for the UI and
schedule calculations), `scan_policy` (scan/remediation timeout budget), `oidc`
(OIDC SSO identity-provider config), `ldap` (LDAP/Active Directory directory
config), `audit_forward` (external SIEM/collector audit forwarding). All three
are JSON; `oidc` and `ldap` hold the IdP/directory configuration with the
client/bind secret sealed at rest (the read path redacts it).

---

## Sequences

- `ssh_cert_serial_seq` — `BIGINT START WITH 1 INCREMENT BY 1`. Source of unique,
  never-reused certificate serials for revocation (KRL) and audit.
