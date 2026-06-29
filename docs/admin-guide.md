# Fleet Terminal — Administrator Guide

This guide is for operators who deploy and administer Fleet Terminal: bootstrap,
users, roles, groups, hosts, settings, and day-to-day operations.

## 1. Deploy the stack

Fleet Terminal runs entirely in Docker. From the repository root:

```sh
make env      # create .env from .env.example
# edit .env: set strong secrets for production (see below)
make up       # build & start the full stack (+ local test fabric)
make ps       # confirm services are healthy
make logs     # tail logs
```

`make up` starts PostgreSQL, Redis, the backend, the frontend, and a local test
fabric (jump host + sample managed hosts). For a production-style stack without
the test fabric, use `make up-app`. Kubernetes manifests are in `deploy/k8s/`.

Check health any time:

```sh
curl -s http://localhost:8080/health   # {"status":"ok"}
curl -s http://localhost:8080/ready    # {"status":"ready"} once the DB is up
```

### Production secrets

Set these in `.env` (generate with `openssl rand -hex 32`). In `production`
(`FLEET_ENV=production`) the backend refuses to start without them:

| Variable | Requirement |
|----------|-------------|
| `FLEET_JWT_SECRET` | ≥ 32 bytes — signs access tokens |
| `FLEET_CSRF_SECRET` | ≥ 16 bytes — CSRF double-submit |
| `FLEET_CA_PASSPHRASE` | ≥ 16 bytes — encrypts the CA private key at rest |
| `FLEET_COOKIE_SECURE` | `true` when served over HTTPS |
| `FLEET_PUBLIC_URL` | your external base URL (cookies/CORS) |

## 2. Bootstrap the first administrator

On first run, no users exist and the **bootstrap wizard** is open. This is a
one-time flow that creates the initial **Super Administrator**.

1. Open the frontend; it detects `GET /api/v1/bootstrap/status` →
   `{"bootstrapAvailable": true}` and shows the wizard.
2. Enter a username, email, display name, and a password that satisfies the
   password policy (default: ≥12 chars, upper/lower/digit/symbol).
3. Submit. The backend creates the user with `is_super_admin = true`, grants the
   built-in **Super Administrator** role, and writes a `bootstrap.init` audit
   event.

The wizard **permanently closes** as soon as any user exists — subsequent calls
to `/api/v1/bootstrap/init` return `409`. It can only be reopened through the
offline recovery procedure (see [Disaster Recovery](./disaster-recovery.md)).

> You can also disable bootstrap entirely with `FLEET_ALLOW_BOOTSTRAP=false`.

CLI equivalent (useful for headless setup):

```sh
curl -s http://localhost:8080/api/v1/bootstrap/init \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","email":"admin@example.com","displayName":"Admin","password":"<strong>"}'
```

## 3. Built-in roles & permissions

RBAC is backend-authoritative. The following roles are seeded:

| Role | Capabilities |
|------|--------------|
| **Super Administrator** | `Admin.All` — wildcard, unrestricted |
| **Administrator** | every permission except the `Admin.All` wildcard |
| **Operator** | `Host.View`, `Host.Connect`, `Host.Sudo`, `Host.Scan`, `Session.Start`, `Session.Replay`, `File.Transfer`, `Approval.Request`, `Assistant.Use` |
| **Auditor** | `Host.View`, `Host.Scan`, `Audit.View`, `Audit.Export`, `Session.Replay` |
| **Read-Only** | `Host.View` |

The full permission catalog is in [database.md](./database.md#permissions). You
can create custom roles and assign any subset of permissions.

> `Host.Connect`, `Host.Scan`, `Host.Remediate`, and `File.Transfer` are **also**
> gated by host access — the permission lets a user *attempt* the action, but they
> still need a group / direct / temporary grant to the specific host (super admins
> bypass). So granting `Host.Scan` to Auditors only lets them scan hosts they can reach.

> **`Host.Remediate`** lets a user **apply OpenSCAP fixes**, which *modify host
> configuration* and are not automatically reversible. It is granted to
> **Administrator only** by default. Fixes for SSH/firewall/lockout rules are
> flagged "access-impacting" in the UI and require an extra confirmation, since
> they can sever Fleet's own access to the host.

### Root vs. login-only access (`Host.Sudo`)

Enrolled hosts have **two shared login accounts**, and a connecting user lands in
one of them based on the **`Host.Sudo`** permission:

- **With `Host.Sudo`** (or a Super Administrator) → the privileged account
  (`fleet`) with **passwordless sudo** — full root.
- **Without `Host.Sudo`** → the **login-only** account (`fleet-login`) — a normal
  shell with **no sudo**.

This lets you grant a user terminal/SFTP access to a host **without** giving them
root: assign them a role that has `Host.Connect` but **not** `Host.Sudo` (e.g.
clone Operator and clear `Host.Sudo`). Either way, every session still uses a
unique per-user certificate and is fully recorded and audited.

> `Host.Sudo` is granted to **Administrator** and **Operator** by default, so
> upgrades preserve the previous "connect = root" behavior. The login-only
> account is created **at enrollment** — hosts enrolled before this feature must
> be **re-enrolled** (Hosts → Enroll → *Already trusts the Fleet CA*) before
> login-only users can connect to them.

## 4. Manage users

(Requires `User.*` / `Role.Edit` / `Group.Edit` permissions; the admin module
endpoints are under `/api/v1/users`, `/roles`, `/groups`.)

- **Create:** `POST /users` with `username`, `email`, `displayName`, `password`,
  optional `isSuperAdmin`, `mustChangePassword`.
- **Edit / disable / unlock:** `PUT /users/{id}`, `POST /users/{id}/disable`,
  `POST /users/{id}/unlock` (clears lockout from failed logins).
- **Reset password:** `POST /users/{id}/reset-password` (set `mustChangePassword`
  to force a change at next login).
- **Assign roles:** in the UI, **Users → Manage roles** (shield icon) toggles a
  user's roles; via API `POST/DELETE /users/{id}/roles/{roleId}`.
- **Group membership:** assign users to groups in the UI from **Groups → Manage
  members** (people icon), or per user via `POST/DELETE /users/{id}/groups/{groupId}`.
- **Require MFA (per user):** `POST /users/{id}/require-mfa` `{"require": true}` —
  forces TOTP enrollment at the user's next sign-in before a session is issued.
- **View accessible hosts:** `GET /users/{id}/hosts` lists every host a user can
  currently reach (the at-a-glance access view).

## 5. Manage roles & groups

- **Roles:** `POST /roles`, `DELETE /roles/{id}` (built-in roles are protected),
  `PUT /roles/{id}/permissions` with `{"permissions": ["Host.View", …]}`.
- **Permissions catalog:** `GET /permissions`.
- **Groups:** `POST /groups`, `DELETE /groups/{id}`. Group membership is one way
  host access is granted — a user can connect to a host when they share a group
  with it. Manage a group's **members** from **Groups → Manage members**; add the
  group to **hosts** from a host's **Manage access** dialog (or
  `POST /hosts/{id}/groups/{groupId}`). So: put users in a group, add the group to
  hosts, and every member can reach every host in it.

## 6. Manage hosts & access

Add hosts to the inventory (`POST /hosts`, requires `Host.Enroll`), then enroll
them so they trust the Fleet user CA — see the
[Host Enrollment Guide](./host-enrollment-guide.md).

**Authorize users** (no host is reachable by default). A user can reach a host via:

- a **shared group** (above), or
- a **direct grant** — `POST /hosts/{id}/users/{userId}` (host's *Manage access*
  dialog → *Individual users*), or
- a **just-in-time** approval grant.

`GET /hosts/{id}/access` returns a host's groups + directly-granted users.

`GET /hosts/stats/status` returns live counts (online / offline / unknown) for
dashboards.

## 7. System settings

`System.Configure` holders manage settings via `/api/v1/settings`:

| Key | Default | Controls |
|-----|---------|----------|
| `password_policy` | min 12, upper/lower/digit/symbol, history 5 | password complexity + reuse |
| `lockout_policy` | max 5 failed, 15 min lockout | account lockout |
| `session_policy` | idle 30 min, absolute 12 h | session lifetime |
| `require_mfa` | `{"enabled": false}` | when on, **all** users must enroll a second factor (Users → *Require MFA for all*) |
| `branding` | `{"app_name": "Fleet Terminal"}` | application name shown on the login screen, top bar, dashboard, and browser tab |
| `assistant` | `{"enabled": false, "ollamaUrl": "", "model": ""}` | local-Ollama AI assistant (read-only NL queries over fleet data); edit via **Settings → AI assistant** |

The **Settings → Branding** card edits the application name in the UI; the change
takes effect immediately (no rebuild) and is served publicly so the login screen
reflects it.

Per-IP rate limits and session/cert TTLs are environment variables
(`FLEET_RATE_LIMIT_*`, `FLEET_SESSION_*`, `FLEET_*_TTL`) — see
[deployment.md](./deployment.md).

## 8. Audit & monitoring

- **Audit log:** `GET /api/v1/audit` (filter by `action`, `actor`). Every state
  change is recorded in a hash-chained log.
- **Integrity check:** `GET /api/v1/audit/verify` → `{"intact":true,"brokenAtSeq":0}`.
  Run this periodically; a non-zero `brokenAtSeq` indicates tampering.
- **Export:** `GET /api/v1/audit/export` streams the full chain for archival.
- **Metrics:** scrape `GET /metrics` (Prometheus). See [Security Guide](./security-guide.md).

## 9. Certificates

Manage the CA and certificate lifecycle (`Certificate.Manage`) under
`/api/v1/certificates`: list issued certs, rotate the CA, revoke a serial, and
fetch the KRL. Details in [certificate-lifecycle.md](./certificate-lifecycle.md).

## 10. Routine operations

| Task | Command / endpoint |
|------|--------------------|
| Tail logs | `make logs` |
| Restart stack | `make down && make up` |
| Stop (keep data) | `make down` |
| Wipe everything | `make clean` (**destroys volumes**) |
| Health / readiness | `GET /health`, `GET /ready` |
| Verify audit chain | `GET /api/v1/audit/verify` |

For backup, restore, and recovery, see [Disaster Recovery](./disaster-recovery.md).
