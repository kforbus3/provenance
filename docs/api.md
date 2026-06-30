# Fleet Terminal — REST API Reference

All application endpoints are served under the versioned prefix **`/api/v1`**.
Operational endpoints (`/health`, `/ready`, `/version`, `/metrics`) are served at
the root.

## Conventions

- **Format:** request and response bodies are JSON (`Content-Type: application/json`).
- **Authentication:** authenticated endpoints require a bearer access token:
  `Authorization: Bearer <accessToken>`. The token is obtained from
  `POST /api/v1/auth/login` and refreshed via `POST /api/v1/auth/refresh`.
- **Authorization:** authorization is enforced server-side. Each route below
  lists its **Required permission**. The holder of `Admin.All` (Super
  Administrator) passes every permission check. Missing permission → `403`.
- **CSRF:** cookie-authenticated, state-changing calls (`refresh`, `logout`)
  require the double-submit header `X-CSRF-Token: <csrfToken>` matching the
  `fleet_csrf` cookie.
- **Errors:** failures return `{"error": "<message>"}` with an appropriate HTTP
  status (`400`, `401`, `403`, `404`, `409`, `500`).
- **Pagination:** list endpoints accept `?limit=&offset=` query parameters.

> Note on mounting: every module is wired in `registerRoutes` (`server.go`).
> `bootstrap`, `auth`, `hosts`, and `certificates` are mounted there directly; the
> `terminal`, `enrollment`, `ws`, `sftp`, `scan`, `assistant`, `playbook`,
> `notify`, `scheduler`, `backup`, `admin`, `auditapi`, `sessionsapi`,
> `approvals`, and `system` modules each expose a `Mount` function that attaches
> at the same `/api/v1` seam. Paths and permissions below are taken directly from
> each module's `Mount`.

---

## Operational (unauthenticated)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness. `{"status":"ok"}` |
| GET | `/ready` | Readiness; pings the DB. `200 {"status":"ready"}` or `503 {"status":"db_unavailable"}` |
| GET | `/version` | `{"version":"<build>","environment":"production","appName":"Fleet Terminal"}` |
| GET | `/metrics` | Prometheus metrics (text exposition format) |
| GET | `/api/v1/ping` | `{"pong":"ok"}` |

---

## Bootstrap

First-run wizard. Intentionally unauthenticated — self-gated on the absence of
any user account and on `FLEET_ALLOW_BOOTSTRAP`.

| Method | Path | Required permission |
|--------|------|---------------------|
| GET | `/api/v1/bootstrap/status` | none |
| POST | `/api/v1/bootstrap/init` | none (only works while zero users exist) |

**`GET /bootstrap/status`** → `{"bootstrapAvailable": true}`

**`POST /bootstrap/init`**
```json
{ "username": "admin", "email": "admin@example.com",
  "displayName": "Site Admin", "password": "correct horse battery staple 9!" }
```
→ `201 Created`
```json
{ "status": "bootstrapped",
  "user": { "id": "…", "username": "admin", "isSuperAdmin": true } }
```
Returns `409` once any user exists, `400` on weak password.

---

## Auth

| Method | Path | Required permission |
|--------|------|---------------------|
| POST | `/api/v1/auth/login` | none |
| POST | `/api/v1/auth/refresh` | none (uses refresh cookie) |
| POST | `/api/v1/auth/mfa/verify` | none (uses challenge) |
| POST | `/api/v1/auth/mfa/setup/begin` | none (uses setup token) |
| POST | `/api/v1/auth/mfa/setup/confirm` | none (uses setup token) |
| POST | `/api/v1/auth/logout` | authenticated |
| GET | `/api/v1/auth/me` | authenticated |
| POST | `/api/v1/auth/change-password` | authenticated |
| GET/POST | `/api/v1/auth/mfa[/totp/...]` | authenticated |
| GET | `/api/v1/auth/oidc/status` | none (login-page probe) |
| GET | `/api/v1/auth/oidc/login` | none (redirects to the IdP) |
| GET | `/api/v1/auth/oidc/callback` | none (completes the auth-code flow) |
| GET | `/api/v1/auth/oidc/config` | `System.Configure` |
| PUT | `/api/v1/auth/oidc/config` | `System.Configure` |
| GET | `/api/v1/auth/ldap/config` | `System.Configure` |
| PUT | `/api/v1/auth/ldap/config` | `System.Configure` |

**`POST /auth/login`**
```json
{ "username": "admin", "password": "…" }
```
→ `200 OK` (also sets `fleet_refresh`, `fleet_sid`, `fleet_csrf` cookies)
```json
{ "accessToken": "eyJ…", "accessExpiresAt": "2026-06-26T12:15:00Z",
  "csrfToken": "…", "user": { "id": "…", "username": "admin", "roles": ["Super Administrator"] },
  "mustChangePassword": false }
```

If the account has a confirmed factor, login returns `{ "mfaRequired": true,
"challenge": "…" }` — exchange it at `POST /auth/mfa/verify` `{ challenge, code }`.
If MFA is **required but not enrolled**, login returns `{ "mfaEnrollmentRequired":
true, "setupToken": "…" }`; enroll via `POST /auth/mfa/setup/begin` `{ setupToken }`
(returns a TOTP secret) then `POST /auth/mfa/setup/confirm` `{ setupToken, code }`,
which completes login. No session is issued until a factor is confirmed.

When local authentication fails and an LDAP/Active Directory directory is
configured and enabled, login falls back to verifying the credentials against
the directory (finding or provisioning the matching Fleet account) before
returning `401`.

**`POST /auth/refresh`** → rotates tokens using the `fleet_refresh` + `fleet_sid`
cookies; returns a fresh `accessToken`, `accessExpiresAt`, and `csrfToken`.

**`GET /auth/me`** →
```json
{ "user": { "id": "…", "username": "admin", "roles": [...], "groups": [...] },
  "permissions": ["Admin.All"], "isSuperAdmin": true }
```

**`POST /auth/change-password`**
```json
{ "currentPassword": "…", "newPassword": "…" }
```
→ `{"status":"password_changed"}`

### OIDC single sign-on

The three browser-facing OIDC routes are public (a WebSocket-style redirect flow
cannot carry a bearer token); the config routes require `System.Configure`.

**`GET /auth/oidc/status`** → the login page polls this to decide whether to show
the SSO button → `{ "enabled": true, "buttonText": "Sign in with SSO" }`
(`enabled` is true only when SSO is configured with an issuer and client id).

**`GET /auth/oidc/login`** → stores short-lived `state`/`nonce`/PKCE cookies and
`302`-redirects to the identity provider's authorization endpoint. Redirects to
`/login?sso=disabled|error` if SSO is off or provider discovery fails.

**`GET /auth/oidc/callback`** → the IdP redirects here with `code`/`state`. The
backend validates state, exchanges the code, verifies the ID token
(signature/issuer/audience/nonce), finds-or-provisions the user, issues a Fleet
session (sets the auth cookies), and `302`-redirects into the app (`/`). On
failure it redirects to `/login?sso=…`.

**`GET /auth/oidc/config`** → `{ "config": { … }, "secretSet": true }` — the
current OIDC config with the client secret redacted (`secretSet` reports whether
one is stored). **`PUT /auth/oidc/config`** saves the config (stored under the
`oidc` setting); a newly-supplied `clientSecret` is sealed at rest and otherwise
the stored secret is preserved → `{ "saved": true }`.

### LDAP / Active Directory

**`GET /auth/ldap/config`** / **`PUT /auth/ldap/config`** (`System.Configure`) —
read/write the LDAP/AD directory config (stored under the `ldap` setting). As
with OIDC, the bind password is write-only on input and sealed at rest; the read
path redacts it. When enabled, this directory backs the `POST /auth/login`
fallback described above.

---

## Hosts

Inventory CRUD. The list endpoint shows all hosts to holders of `Host.Enroll` /
`Admin.All`; otherwise it is restricted to hosts the principal can access.

| Method | Path | Required permission |
|--------|------|---------------------|
| GET | `/api/v1/hosts` | `Host.View` |
| GET | `/api/v1/hosts/{id}` | `Host.View` |
| GET | `/api/v1/hosts/stats/status` | `Host.View` |
| POST | `/api/v1/hosts` | `Host.Enroll` |
| PUT | `/api/v1/hosts/{id}` | `Host.Edit` |
| DELETE | `/api/v1/hosts/{id}` | `Host.Delete` |
| POST | `/api/v1/hosts/{id}/groups/{groupId}` | `Host.Edit` |
| DELETE | `/api/v1/hosts/{id}/groups/{groupId}` | `Host.Edit` |
| GET | `/api/v1/hosts/{id}/access` | `Host.Edit` |
| POST | `/api/v1/hosts/{id}/users/{userId}` | `Host.Edit` |
| DELETE | `/api/v1/hosts/{id}/users/{userId}` | `Host.Edit` |
| POST | `/api/v1/hosts/{id}/enroll` | `Host.Enroll` |
| GET | `/api/v1/hosts/{id}/enroll/script` | `Host.Enroll` |
| POST | `/api/v1/hosts/{id}/enroll/finish` | `Host.Enroll` |
| GET (WS) | `/api/v1/hosts/{id}/enroll/agent` | `Host.Enroll` (token) |

**Enrollment methods** — `POST /hosts/{id}/enroll` body selects `method`:
`"password"` (`+ bootstrapUser, password`), `"key"` (`+ privateKey, keyPassphrase`),
`"trusted"`, or omit for trusted. The body also accepts `sudoPassword`,
`wgEndpoint` (the jump host's public WireGuard endpoint), `viaJump` (route the
bootstrap through the jump host), and `skipWireGuard` (boolean — enroll a host
that is directly reachable from the jump host, skipping WireGuard tunnel
provisioning). `agent` uses the WebSocket (`fleet-enroll-agent` bridge); the
no-install flow uses `GET …/enroll/script` (pipe through your own ssh) then
`POST …/enroll/finish` `{ "hostPublicKey": "…" }`. See the
[Host Enrollment Guide](./host-enrollment-guide.md).

**`GET /hosts/{id}/access`** → `{ "groups": ["ops"], "users": [ … ] }`

**`POST /hosts`**
```json
{ "hostname": "web-01", "description": "frontend node", "environment": "production",
  "owner": "platform", "address": "10.0.1.5", "wgAddress": "10.9.0.5",
  "sshPort": 22, "sshUser": "fleet", "tags": ["web","edge"] }
```
→ `201` with the created host object.

**`GET /hosts`** → `{ "hosts": [ … ], "count": 12 }`

**`GET /hosts/stats/status`** → counts by status, e.g. `{"online":9,"offline":2,"unknown":1}`

---

## Users, Roles, Groups, Settings (admin module)

### Users

| Method | Path | Required permission |
|--------|------|---------------------|
| GET | `/api/v1/users` | `User.Edit` |
| POST | `/api/v1/users` | `User.Create` |
| GET | `/api/v1/users/{id}` | `User.Edit` |
| PUT | `/api/v1/users/{id}` | `User.Edit` |
| DELETE | `/api/v1/users/{id}` | `User.Delete` |
| POST | `/api/v1/users/{id}/disable` | `User.Edit` |
| POST | `/api/v1/users/{id}/unlock` | `User.Edit` |
| POST | `/api/v1/users/{id}/require-mfa` | `User.Edit` |
| GET | `/api/v1/users/{id}/hosts` | `User.Edit` |
| POST | `/api/v1/users/{id}/reset-password` | `User.ResetPassword` |
| POST | `/api/v1/users/{id}/roles/{roleId}` | `Role.Edit` |
| DELETE | `/api/v1/users/{id}/roles/{roleId}` | `Role.Edit` |
| POST | `/api/v1/users/{id}/groups/{groupId}` | `Group.Edit` |
| DELETE | `/api/v1/users/{id}/groups/{groupId}` | `Group.Edit` |

**`POST /users`**
```json
{ "username": "alice", "email": "alice@example.com", "displayName": "Alice",
  "password": "…", "isSuperAdmin": false, "mustChangePassword": true }
```

**`POST /users/{id}/disable`** → `{ "disabled": true }`

**`POST /users/{id}/reset-password`** → `{ "newPassword": "…", "mustChangePassword": true }`

### Roles & permissions

| Method | Path | Required permission |
|--------|------|---------------------|
| GET | `/api/v1/roles` | `Role.Edit` |
| POST | `/api/v1/roles` | `Role.Create` |
| DELETE | `/api/v1/roles/{id}` | `Role.Delete` |
| PUT | `/api/v1/roles/{id}/permissions` | `Role.Edit` |
| GET | `/api/v1/permissions` | `Role.Edit` |

**`POST /roles`** → `{ "name": "Deployer", "description": "CI/CD operators" }`

**`PUT /roles/{id}/permissions`** → `{ "permissions": ["Host.View","Host.Connect","Session.Start"] }`

### Groups

| Method | Path | Required permission |
|--------|------|---------------------|
| GET | `/api/v1/groups` | `Group.Edit` |
| POST | `/api/v1/groups` | `Group.Create` |
| DELETE | `/api/v1/groups/{id}` | `Group.Delete` |

**`POST /groups`** → `{ "name": "web-team", "description": "Owns the web tier" }`

### System settings

| Method | Path | Required permission |
|--------|------|---------------------|
| GET | `/api/v1/settings` | `System.Configure` |
| GET | `/api/v1/settings/{key}` | `System.Configure` |
| PUT | `/api/v1/settings/{key}` | `System.Configure` |

Known setting keys (seeded): `password_policy`, `lockout_policy`,
`session_policy`, `require_mfa`, `branding`, `assistant`. Additional keys written
on first use: `notifications`, `backup_policy`, `timezone`, `scan_policy`,
`oidc`, `ldap`, `audit_forward`. Several of these have dedicated endpoints (e.g.
notifications, backups, timezone, OIDC/LDAP config, audit forwarding) but are
also readable/writable through this generic settings interface.

---

## Audit

Hash-chained, tamper-evident audit log.

| Method | Path | Required permission |
|--------|------|---------------------|
| GET | `/api/v1/audit` | `Audit.View` |
| GET | `/api/v1/audit/verify` | `Audit.View` |
| GET | `/api/v1/audit/export` | `Audit.Export` |

**`GET /audit?action=host.create&actor=<uuid>&limit=50&offset=0`** →
```json
{ "events": [
    { "seq": 42, "id": "…", "actorName": "admin", "action": "host.create",
      "targetKind": "host", "targetId": "…", "prevHash": "…", "hash": "…",
      "createdAt": "2026-06-26T11:00:00Z" }
  ], "count": 1 }
```

**`GET /audit/verify`** → `{ "intact": true, "brokenAtSeq": 0 }` (a non-zero
`brokenAtSeq` identifies the first tampered/broken row).

**`GET /audit/export`** → streams the entire chain as a JSON array with
`Content-Disposition: attachment; filename="audit-export.json"`.

### Audit forwarding

Forwarding of audit events to an external SIEM/collector. All routes require
`System.Configure`.

| Method | Path | Required permission |
|--------|------|---------------------|
| GET | `/api/v1/audit/forwarding` | `System.Configure` |
| PUT | `/api/v1/audit/forwarding` | `System.Configure` |
| POST | `/api/v1/audit/forwarding/test` | `System.Configure` |

**`GET /audit/forwarding`** → the current forwarding config (`{ enabled, type, … }`,
stored under the `audit_forward` setting). **`PUT /audit/forwarding`** saves it and
echoes the saved config. **`POST /audit/forwarding/test`** sends a test event using
the posted config → `{ "ok": true }` or `{ "ok": false, "error": "…" }`.

---

## Sessions (replay)

Read-only access to recorded SSH sessions and their `asciicast-v2` recordings.

| Method | Path | Required permission |
|--------|------|---------------------|
| GET | `/api/v1/sessions` | `Session.Replay` |
| GET | `/api/v1/sessions/{id}` | `Session.Replay` |
| GET | `/api/v1/sessions/{id}/recording` | `Session.Replay` |

**`GET /sessions?user=<uuid>&host=<uuid>&limit=&offset=`** →
`{ "sessions": [ … ], "count": n }`

**`GET /sessions/{id}/recording`** →
```json
{ "recording": { "format": "asciicast-v2", "durationMs": 84200, "sha256": "…" },
  "cast": "{\"version\":2,...}\n[0.1,\"o\",\"...\"]\n…" }
```

---

## Approvals (just-in-time access)

| Method | Path | Required permission |
|--------|------|---------------------|
| POST | `/api/v1/approvals` | `Approval.Request` |
| GET | `/api/v1/approvals/targets` | `Approval.Request` |
| GET | `/api/v1/approvals` | `Approval.Request` (deciders see all; requesters see their own) |
| GET | `/api/v1/approvals/mine` | `Approval.Request` |
| GET | `/api/v1/approvals/grants/mine` | `Approval.Request` |
| POST | `/api/v1/approvals/{id}/decide` | `Approval.Decide` |

**`GET /approvals/targets?kind=host|group&q=<text>`** → server-side search for
the access-request picker. Matches hosts (or groups) by name, case-insensitive
substring, capped at 50 results so it scales to large fleets. Targets the
requester can already reach (membership, direct/temporary grant, or super admin)
are excluded — so a super admin's picker is empty. `kind` defaults to `host`;
`q` empty returns the first matches.
```json
{ "targets": [ { "id": "…", "name": "web-01", "environment": "prod" } ] }
```

**`POST /approvals`**
```json
{ "targetKind": "host", "hostId": "…", "reason": "incident #4821",
  "ticketRef": "INC-4821", "requestedSecs": 3600 }
```
(`targetKind` is `host` or `group`; supply `hostId` or `groupId` accordingly.)

**`POST /approvals/{id}/decide`**
```json
{ "decision": "approve", "note": "approved for 30m", "grantedSecs": 1800 }
```
An approval mints a `temporary_permissions` grant that expires automatically.

**`GET /approvals/grants/mine`** → `{ "grants": [ … ], "count": n }`

---

## SFTP (audited file transfer)

Audited file transfer to managed hosts, brokered through the SSH gateway — the
browser never speaks SFTP. All routes require `File.Transfer` **and** access to
the target host (group / direct / temporary grant; super admins bypass), the same
gate as terminals. Sudo-tier callers (`Host.Sudo` or super admin) land in the
host's privileged account; everyone else in its login-only account.

| Method | Path | Required permission |
|--------|------|---------------------|
| GET | `/api/v1/hosts/{id}/sftp/list` | `File.Transfer` |
| GET | `/api/v1/hosts/{id}/sftp/download` | `File.Transfer` |
| GET | `/api/v1/hosts/{id}/sftp/download-dir` | `File.Transfer` |
| POST | `/api/v1/hosts/{id}/sftp/upload` | `File.Transfer` |
| GET | `/api/v1/hosts/{id}/sftp/transfers` | `File.Transfer` |

- **`GET …/sftp/list?path=`** → `{ "path": "<abs>", "entries": [ { name, size, isDir, mode, modTime } ] }` (defaults to `.`).
- **`GET …/sftp/download?path=`** → streams the file (`application/octet-stream`, `Content-Disposition: attachment`).
- **`GET …/sftp/download-dir?path=`** → streams the directory recursively as a `.tar` archive (`application/x-tar`).
- **`POST …/sftp/upload?path=<dir>&name=<file>`** → request body is the raw file bytes; honours the configured upload cap (oversized → `413`). `name` may contain a relative subpath for folder uploads (traversal rejected). → `{ "path": "…", "size": n }`.
- **`GET …/sftp/transfers`** → recent transfer audit records for the host (`{ "transfers": [ … ] }`).

Every transfer is recorded in `sftp_transfers` and written to the audit log.

---

## Security scans (OpenSCAP)

All require `Host.Scan` **and** access to the target host (group / direct /
temporary grant; super admins bypass) — the same gate as terminals/SFTP. The
report route authenticates via a `token` query param so it can be
embedded/downloaded by the browser.

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/v1/hosts/{id}/scan/profiles` | Discover profiles (no install); `{ installed, installing, datastream, profiles }` |
| POST | `/api/v1/hosts/{id}/scan/prepare` | Install the scanner + content in the background so profiles populate |
| POST | `/api/v1/hosts/{id}/scan` | Start a scan; body `{ "profile": "<id>" }` (empty = standard) |
| GET | `/api/v1/hosts/{id}/scans` | List recent scans for the host |
| GET | `/api/v1/scans/{id}` | One scan's status + summary (poll while running) |
| GET | `/api/v1/scans/{id}/report?token=<jwt>[&download=1]` | Stored HTML report (sandboxed view / download) |
| GET | `/api/v1/scans/{id}/findings` | `Host.Scan` — failed rules (id, title, severity, accessImpacting) |
| POST | `/api/v1/scans/{id}/remediation/preview` | `Host.Remediate` — `{ruleIds}` → `{script}` (no changes) |
| POST | `/api/v1/scans/{id}/remediate` | `Host.Remediate` — `{ruleIds, confirmAccessImpacting}` → run id (async); 409 if access-impacting rules selected without confirmation |
| GET | `/api/v1/remediations/{id}` | `Host.Remediate` — run status/output/exit + verification re-scan id |
| GET | `/api/v1/hosts/{id}/support-bundle` | `Host.Scan` + host access — streams a `.tar.gz` of host diagnostics + recent logs (collected over SSH; nothing stored) |

Remediation applies `oscap`-generated bash fixes for the **selected** failed rules
over the gateway (sudo), then re-scans to verify. All scan/remediation routes also
require host access. Rules touching SSH/firewall/lockout are flagged
`accessImpacting` and need an explicit confirmation.

The backend runs `oscap` over the gateway as the privileged host account
(installing `openscap-scanner` + SCAP content if missing), stores the HTML report
under `FLEET_SCAN_DIR`, and records a parsed summary:
```json
{ "id":"…","status":"completed","profile":"xccdf_org.ssgproject.content_profile_standard",
  "score":86.7,"passCount":210,"failCount":32,"otherCount":40,"totalRules":282 }
```

---

## AI assistant (Ollama)

Read-only natural-language queries over fleet data via a local Ollama instance.
The model only calls a curated set of read-only tools (no SQL, no actions); all
results are scoped to what the caller can access and every question is audited.

| Method | Path | Gate |
|--------|------|------|
| GET | `/api/v1/assistant/status` | `Assistant.Use` — `{enabled, model, reachable, ready}` |
| GET | `/api/v1/assistant/models?url=` | `System.Configure` — list Ollama models (for setup) |
| POST | `/api/v1/assistant/ask` | `Assistant.Use` — `{question}` → `202 {id}` (async) |
| GET | `/api/v1/assistant/ask/{id}` | `Assistant.Use` — poll → `{status, answer, hosts[]}` |

The model is offered these tools (each scoped to the caller's access, several
additionally gated by the caller's permissions):

- **`query_hosts`** — find managed hosts by structured filters. Returns, per host:
  hostname, environment, status, IP, OS/kernel/architecture, CPU/memory, SSH
  version, uptime, disk/memory/load metrics, latency, WireGuard health, last-seen,
  groups, tags, owner, enrolled state, and pending-update counts
  `updatesAvailable` / `securityUpdates`. Filters include
  `updatesAvailableMin` and `securityUpdatesMin` (e.g. `1` = hosts that have any
  updates / security updates available).
- **`list_sessions`** — currently-connected SSH sessions (gated by `Session.Replay`).
- **`host_detail`** — full detail for one host by exact hostname (filesystems, NICs).
- **`recent_scans`** — recent OpenSCAP scans, scheduled or manual (gated by `Host.Scan`).
- **`recent_playbook_runs`** — recent Ansible playbook runs, scheduled or manual
  (gated by `Playbook.Run`).

Configured via the `assistant` setting (`{enabled, ollamaUrl, model}`). Asks run
in the background (local inference can exceed the request timeout); poll the `id`.

---

## Playbooks (Ansible)

Author, validate, and run Ansible playbooks. Authoring/validation requires
`Playbook.Edit`; execution requires `Playbook.Run` (both Administrator-only by
default). Run routes additionally enforce host access (group / direct / temporary
grant; super admins bypass) for every targeted host.

| Method | Path | Required permission |
|--------|------|---------------------|
| GET | `/api/v1/playbooks` | `Playbook.Edit` |
| POST | `/api/v1/playbooks` | `Playbook.Edit` |
| GET | `/api/v1/playbooks/runner` | `Playbook.Edit` |
| POST | `/api/v1/playbooks/validate` | `Playbook.Edit` |
| POST | `/api/v1/playbooks/lint` | `Playbook.Edit` |
| GET | `/api/v1/playbooks/{id}` | `Playbook.Edit` |
| PUT | `/api/v1/playbooks/{id}` | `Playbook.Edit` |
| DELETE | `/api/v1/playbooks/{id}` | `Playbook.Edit` |
| GET | `/api/v1/playbooks/{id}/versions` | `Playbook.Edit` |
| GET | `/api/v1/playbooks/{id}/versions/{version}` | `Playbook.Edit` |
| POST | `/api/v1/playbooks/{id}/run` | `Playbook.Run` |
| GET | `/api/v1/playbooks/{id}/runs` | `Playbook.Run` |
| GET | `/api/v1/playbook-runs/{runId}` | `Playbook.Run` |

**`POST /playbooks`** / **`PUT /playbooks/{id}`** → `{ "name": "…", "description": "…", "content": "<yaml>" }`.
Saving new content bumps `version` and snapshots the prior content into the
version history.

**`POST /playbooks/validate`** / **`POST /playbooks/lint`** → `{ "content": "<yaml>" }`
→ syntax-check / `ansible-lint` results. `GET /playbooks/runner` →
`{ "available": true|false }` (whether the runner tooling is installed).

**`POST /playbooks/{id}/run`**
```json
{ "targetKind": "host", "hostIds": ["…"], "checkMode": false }
```
`targetKind` is `host` (supply `hostIds`, or `targetId` for a single host) or
`group` (supply `groupId`; only hosts the caller can reach are targeted).
`checkMode` runs `ansible --check` (dry run). → `202` with the run record. Poll
`GET /playbook-runs/{runId}` for streaming status/output;
`GET /playbooks/{id}/runs` lists recent runs.

---

## Schedules (recurring scans & playbook runs)

Recurring scans and playbook runs. `Schedule.Manage` (Administrator-only by
default) is required for all schedule routes. Schedules are disabled by default; a
background engine fires due, enabled schedules through the normal scan/playbook
paths. The display timezone is readable by any signed-in user but only writable
with `System.Configure`.

| Method | Path | Required permission |
|--------|------|---------------------|
| GET | `/api/v1/timezone` | authenticated |
| PUT | `/api/v1/timezone` | `System.Configure` |
| GET | `/api/v1/schedules` | `Schedule.Manage` |
| POST | `/api/v1/schedules` | `Schedule.Manage` |
| PUT | `/api/v1/schedules/{id}` | `Schedule.Manage` |
| DELETE | `/api/v1/schedules/{id}` | `Schedule.Manage` |
| POST | `/api/v1/schedules/{id}/enable` | `Schedule.Manage` |
| POST | `/api/v1/schedules/{id}/run` | `Schedule.Manage` |

**`POST /schedules`** / **`PUT /schedules/{id}`**
```json
{ "name": "Nightly scan", "kind": "scan", "enabled": true,
  "targetKind": "host", "targetId": "…",
  "recurrence": { "type": "daily", "timeOfDay": "02:00", "weekday": 0, "everyMinutes": 0 },
  "payload": { } }
```
`kind` is `scan` or `playbook`; `payload` carries the scan/playbook parameters.

**`POST /schedules/{id}/enable`** → `{ "enabled": true|false }`.
**`POST /schedules/{id}/run`** → fires the schedule immediately → `202 { "status": "…" }`.

**`GET /timezone`** → `{ "timezone": "America/New_York" }`. **`PUT /timezone`**
`{ "timezone": "<IANA name>" }` (empty = server default; validated against the
IANA database) recomputes enabled schedules' next-run times.

---

## Notifications

Notification channel and event configuration (`System.Configure` only).

| Method | Path | Required permission |
|--------|------|---------------------|
| GET | `/api/v1/notifications` | `System.Configure` |
| PUT | `/api/v1/notifications` | `System.Configure` |
| POST | `/api/v1/notifications/test` | `System.Configure` |
| GET | `/api/v1/notifications/events` | `System.Configure` |

**`GET /notifications`** → the current config with secrets redacted.
**`PUT /notifications`** → saves the config (stored under the `notifications`
setting) and returns the redacted result. **`POST /notifications/test`**
`{ "channel": "…" }` → sends a test message → `{ "ok": true }` or
`{ "ok": false, "error": "…" }`. **`GET /notifications/events`** → the event-type
catalogue (`{ "events": [ { "key", "label" } ] }`) for the UI matrix.

---

## Backups & system

Encrypted database backups, the on-demand `pg_dump` download, and background-job
status. All require `System.Configure`. The encrypted backup download
authenticates via a `token` query param so the browser can fetch it directly.

| Method | Path | Required permission |
|--------|------|---------------------|
| GET | `/api/v1/system/backups` | `System.Configure` |
| POST | `/api/v1/system/backups` | `System.Configure` |
| GET | `/api/v1/system/backups/{name}?token=<accessToken>` | `System.Configure` (token) |
| GET | `/api/v1/system/backup-policy` | `System.Configure` |
| PUT | `/api/v1/system/backup-policy` | `System.Configure` |
| GET | `/api/v1/system/jobs` | `System.Configure` |
| GET | `/api/v1/system/backup` | `System.Configure` |
| GET | `/api/v1/system/health` | `System.Configure` |

**`GET /system/backups`** → `{ "backups": [ … ], "dir": "<BackupDir>", "count": n }`.
**`POST /system/backups`** → creates an encrypted backup → `201` with its info.
**`GET /system/backups/{name}`** → streams the encrypted backup file
(`application/octet-stream`, token-authenticated).

**`GET /system/backup-policy`** / **`PUT /system/backup-policy`** → the automatic
backup schedule (`{ enabled, intervalHours, … }`, stored under the
`backup_policy` setting).

**`GET /system/jobs`** → `{ "schedulers": [ … ], "enrollmentJobs": [ … ] }`
(background-scheduler snapshot + recent enrollment jobs). **`GET /system/backup`**
streams a logical `pg_dump` of the database as a download
(`application/sql`; `501` if `pg_dump` is unavailable). Restore is an out-of-band
operation and is intentionally not exposed over the web UI.

**`GET /system/health`** → a live status report of Fleet's subsystems for the
admin System Health page. Each component (database, certificate authority, jump
host, Ansible runner, backups, and each background job) is checked with a bounded
timeout so one slow dependency can't stall the report.
```json
{ "overall": "ok",
  "components": [ { "name": "Database", "status": "ok", "detail": "connected" } ],
  "checkedAt": "2026-06-26T11:00:00Z", "version": "<build>" }
```
`status` is `ok`, `warn`, or `error`; `overall` is the worst component status.

---

## Certificates (CA lifecycle)

| Method | Path | Required permission |
|--------|------|---------------------|
| GET | `/api/v1/certificates/ca/pub` | **none** (public key) |
| GET | `/api/v1/certificates` | `Certificate.Manage` |
| GET | `/api/v1/certificates/ca` | `Certificate.Manage` |
| POST | `/api/v1/certificates/ca/rotate` | `Certificate.Manage` |
| GET | `/api/v1/certificates/krl` | `Certificate.Manage` |
| POST | `/api/v1/certificates/{serial}/revoke` | `Certificate.Manage` |

**`GET /certificates/ca/pub`** → `text/plain`, the active user CA public key(s) in
`authorized_keys` format (one per line) for use as `TrustedUserCAKeys`.
Unauthenticated by design — the CA *public* key is not secret. The co-located
jump host polls this to self-trust the CA.

**`GET /certificates/ca`** →
```json
{ "cas": [ { "kind": "user", "fingerprint": "SHA256:…", "active": true } ],
  "activeUserCA": "ssh-ed25519 AAAA… fleet-user-ca" }
```

**`POST /certificates/ca/rotate`** → `{ "status": "rotated", "activeCa": "<id>" }`

**`POST /certificates/{serial}/revoke`** → `{ "reason": "compromised" }` →
`{ "status": "revoked" }`

**`GET /certificates/krl`** → `{ "revokedSerials": [12, 87, 145] }`

See [certificate-lifecycle.md](./certificate-lifecycle.md) for the full lifecycle.

---

## Terminal (WebSocket)

| Method | Path | Required permission |
|--------|------|---------------------|
| GET (Upgrade) | `/api/v1/terminal/{hostId}?token=<accessToken>` | `Host.Connect` + host authorization |

The browser authenticates by passing the short-lived access token as the `token`
query parameter (a WebSocket cannot carry an `Authorization` header). The backend
additionally enforces host authorization (group membership or an active temporary
grant; super admins bypass).

**Client → server** control frames (text):
```json
{ "type": "resize", "cols": 120, "rows": 32 }
{ "type": "data", "data": "ls -la\n" }
```
Binary frames carry raw terminal input. **Server → client** binary frames carry
terminal output; a `{"type":"error","data":"…"}` text frame reports failures.

## Live events (WebSocket)

| Method | Path | Auth |
|--------|------|------|
| GET (Upgrade) | `/api/v1/events/ws?token=<accessToken>` | authenticated |

A fan-out stream the dashboard subscribes to. Server pushes JSON frames:

```json
{ "type": "host.status",   "data": { "hostId": "…", "status": "online", "latencyMs": 12 } }
{ "type": "session.start", "data": { "sshSessionId": "…", "username": "alice", "hostname": "web-01" } }
{ "type": "session.end",   "data": { "sshSessionId": "…", "username": "alice", "hostname": "web-01" } }
```

`host.status` is emitted by the monitor; `session.start`/`session.end` by the
terminal as users connect/disconnect (drives the dashboard's live-sessions panel).

---

## Health & metrics summary

- `GET /health` — process liveness.
- `GET /ready` — DB-backed readiness (used by orchestrators).
- `GET /version` — build version string, runtime environment (`FLEET_ENV`), and the
  customizable application name (public, so the login screen can render it).
- `GET /metrics` — Prometheus counters/histograms (`fleet_http_requests_total`,
  `fleet_http_request_duration_seconds`, plus session/gateway metrics).
