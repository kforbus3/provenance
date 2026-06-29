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

> Note on mounting: `bootstrap`, `auth`, `hosts`, and `certificates` are wired in
> `registerRoutes`. The `admin`, `auditapi`, `sessionsapi`, `approvals`, and
> `terminal` modules each expose `func Mount(r chi.Router, d *app.Deps)` and
> attach at the same `/api/v1` mount seam (`mountModules`). Paths and permissions
> below are taken directly from each module's `Mount`.

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
`"trusted"`, or omit for trusted. `agent` uses the WebSocket (`fleet-enroll-agent`
bridge); the no-install flow uses `GET …/enroll/script` (pipe through your own
ssh) then `POST …/enroll/finish` `{ "hostPublicKey": "…" }`. See the
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

Known setting keys (seeded): `password_policy`, `lockout_policy`, `session_policy`.

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
The model only calls a curated `query_hosts` tool (no SQL, no actions); results
are scoped to hosts the caller can access and every question is audited.

| Method | Path | Gate |
|--------|------|------|
| GET | `/api/v1/assistant/status` | `Assistant.Use` — `{enabled, model, reachable, ready}` |
| GET | `/api/v1/assistant/models?url=` | `System.Configure` — list Ollama models (for setup) |
| POST | `/api/v1/assistant/ask` | `Assistant.Use` — `{question}` → `202 {id}` (async) |
| GET | `/api/v1/assistant/ask/{id}` | `Assistant.Use` — poll → `{status, answer, hosts[]}` |

Configured via the `assistant` setting (`{enabled, ollamaUrl, model}`). Asks run
in the background (local inference can exceed the request timeout); poll the `id`.

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
