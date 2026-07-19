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
> **Administrator only** by default. Fixes for SSH/firewall/lockout rules,
> networking sysctls such as `ip_forward`/`rp_filter`/`route_localnet`, and
> Fleet's privilege path (`sudo_*` such as `noexec`/`requiretty`, and root-login
> lockout) are flagged "access-impacting" in the UI and require an extra
> confirmation, since they can sever Fleet's own access to — or automation of —
> the host. Remediating a **control-plane
> host** (the jump host, a host tagged `control-plane`/`protected`, or one listed
> in `FLEET_CONTROL_PLANE_HOSTS`) requires a second, distinct confirmation because
> hardening the box that runs Fleet can lock Fleet out of the entire fleet.

Three permissions gate the automation features, all granted to **Administrator**
(and Super Administrator) by default:

- **`Playbook.Edit`** — author, validate, and lint Ansible playbooks (§7).
- **`Playbook.Run`** — execute a playbook against hosts (§7). Also gated by host
  access.
- **`Schedule.Manage`** — create and manage recurring scans / playbook runs (§8).

> **`Playbook.Run` is effectively arbitrary root-level change across every
> targeted host** — it runs Ansible as the privileged `fleet` account over the
> same certificate-auth path as scans. Treat it like (in fact, more broadly than)
> `Host.Remediate` and grant it sparingly; it is **not** part of the Operator
> role by default.

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
- **Service accounts (automation):** non-human identities that authenticate to the
  REST API with tokens are managed separately — see §18.

### MFA recovery codes

Users generate **one-time backup codes** that stand in for their authenticator
(TOTP or passkey) when it is lost. This is **self-service** under **Security**
settings, so admins never hold the codes:

- **10 codes** are issued at once and shown **once**; Fleet stores only their
  SHA-256 hashes and can never redisplay them.
- Format `xxxx-xxxx-xxxx`; a user types one at the **normal MFA prompt** — the same
  field as a TOTP code (dashes, spacing, and case are normalized).
- Generation is **refused until a second factor (TOTP or passkey) is confirmed**,
  and generating a fresh set **invalidates the previous set**. Each code is
  single-use; failed attempts feed the same lockout policy as TOTP.

| Action | Endpoint (authenticated, self) |
|--------|--------------------------------|
| Remaining count | `GET /api/v1/auth/mfa/recovery-codes` → `{remaining}` |
| Generate a new set | `POST /api/v1/auth/mfa/recovery-codes` → `{codes:[…]}` (once) |

> A locked-out user with **no** authenticator and **no** remaining codes needs an
> admin to reset their factors. Encourage users to store the codes offline.

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

### Dynamic host groups

A group can carry a **membership rule** over stable host attributes; every host that
matches **joins automatically**, and — because group membership grants host access —
its members immediately gain access to those hosts. Rule fields:

| Field | Match |
|-------|-------|
| `environment` | exact match on the host's environment |
| `tagsAll` | host carries **all** listed tags |
| `tagsAny` | host carries **at least one** listed tag |
| `osContains` | substring of the host's OS string |
| `hostnameContains` | substring of the hostname |

- Only **stable** attributes are used — live metrics are deliberately excluded so
  membership never flaps. An **empty rule matches nothing** (never "all hosts").
- Membership is **materialized** into `host_groups` (the access-check path is
  unchanged) and **auto-reconciles**: recomputed on rule save and by a background
  loop roughly every 3 minutes.
- On a rule-managed (**Dynamic**) group, **manual add/remove is refused** (`409`) —
  edit the rule instead. A rule-less group stays **static/manual** as before.
- The **Groups** page shows a **Dynamic / Manual** badge plus a rule summary, with a
  rule editor to create, edit, or **clear the rule back to manual**.

| Action | Endpoint |
|--------|----------|
| Create a group with an optional rule | `POST /groups` (accepts `rule`) |
| Set / clear a group's rule | `PUT /groups/{id}` (`Group.Edit`) |

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

### Direct-host enrollment (skip WireGuard)

When enrolling a host you can tick **"Directly reachable from the jump host —
skip WireGuard"**. Use it for hosts that already sit on the jump host's LAN (or
for the host that runs Fleet itself). The host is then reached at its
**management address** through the jump host instead of over the WireGuard
overlay; everything else (CA trust, login accounts, scans, sessions) is
unchanged. See the [Host Enrollment Guide](./host-enrollment-guide.md) for the
full enrollment method list.

### Pending package updates

The monitor counts each host's **available package updates** (apt/dnf) during its
hourly facts refresh. They show in a host's **Details** dialog as
`Updates available: N (M security)`, and the AI assistant can answer questions
like "which hosts have security updates" from the same data.

## 7. Ansible playbooks

The **Playbooks** sidebar page (gated by `Playbook.Edit`) lets authors write a
single YAML playbook in an in-browser editor and check it before it ever touches
a host:

- **Validate** — `ansible-playbook --syntax-check`.
- **Lint** — `ansible-lint`.

Both run in a dedicated **`ansible-runner` sidecar** container, configured by
`FLEET_ANSIBLE_RUNNER_URL` (default `http://ansible-runner:8000`). Each save keeps
a version history.

**Running** a playbook requires the separate **`Playbook.Run`** permission
(admin-only by default) **plus** access to the target host(s). Runs go against one
or more hosts or a whole **group**, through the Fleet jump host as the privileged
`fleet` account via certificate auth — the same path scans use. **Dry-run
(Ansible check mode) is on by default**; clear it to make real changes. Output
streams live and is retained in a per-playbook **run history**.

Write plays that target `hosts: all` — Fleet supplies the inventory for the hosts
you select.

> **Security:** `Playbook.Run` is effectively **arbitrary root-level change across
> every targeted host**. Restrict it to trusted administrators, and keep the
> check-mode default on while developing a playbook.

| Action | Endpoint |
|--------|----------|
| List / create / edit / delete playbooks | `GET/POST/PUT/DELETE /api/v1/playbooks[/{id}]` (`Playbook.Edit`) |
| Validate / lint | `POST /api/v1/playbooks/{validate,lint}` (`Playbook.Edit`) |
| Run | `POST /api/v1/playbooks/{id}/run` (`Playbook.Run` + host access) |
| Run history / status | `GET /api/v1/playbooks/{id}/runs`, `GET /api/v1/playbook-runs/{runId}` |

## 8. Schedules

The **Schedules** page (gated by `Schedule.Manage`, admin-only) creates recurring
**scans** or **playbook runs**. A schedule has a **target** (a host or a group), a
**recurrence** — `interval` (every N minutes), `daily`, or `weekly` (with a
time-of-day, in the app's configured time zone) — and shows **next** / **last**
run.

- **New schedules are disabled by default**; an operator flips the **enable**
  toggle to activate them.
- **Run now** triggers an immediate run without changing the schedule.
- Scheduled runs reuse the normal scan / playbook paths, so they appear in the
  usual run history, tagged **scheduled** vs **manual**.

The engine wakes once a minute to evaluate due schedules. Clock times are
interpreted in the time zone set under **Settings → Time zone** (§9).

| Action | Endpoint |
|--------|----------|
| List / create / edit / delete | `GET/POST/PUT/DELETE /api/v1/schedules[/{id}]` |
| Enable / disable | `POST /api/v1/schedules/{id}/enable` |
| Run now | `POST /api/v1/schedules/{id}/run` |

## 9. System settings

`System.Configure` holders manage settings via `/api/v1/settings`:

| Key | Default | Controls |
|-----|---------|----------|
| `password_policy` | min 12, upper/lower/digit/symbol, history 5 | password complexity + reuse |
| `lockout_policy` | max 5 failed, 15 min lockout | account lockout |
| `session_policy` | idle 30 min, absolute 12 h | session lifetime |
| `require_mfa` | `{"enabled": false}` | when on, **all** users must enroll a second factor (Users → *Require MFA for all*) |
| `branding` | `{"app_name": "Fleet Terminal"}` | application name shown on the login screen, top bar, dashboard, and browser tab |
| `assistant` | `{"enabled": false, "ollamaUrl": "", "model": ""}` | local-Ollama AI assistant — natural-language queries over fleet data + product docs, and (with `Assistant.Act`) actions the user confirms; edit via **Settings → AI assistant** |
| `assistant_actions` | `{"requireApprovalForAll": false, "disabledKinds": []}` | assistant-action policy: force approval for every action, or disable specific action kinds; edit via **Settings → Assistant actions** |
| `scan_policy` | `{"timeoutMinutes": …}` | scan / remediation timeout budget (overrides `FLEET_SCAN_TIMEOUT`, clamped to a sane range) |
| `timezone` | browser-detected IANA zone | display zone for all timestamps + schedule clock-times (§9, Time zone) |
| `notifications` | both channels off | outbound alert channels + event routing (§10) |
| `backup_policy` | `{"enabled": false, "intervalHours": 24, "retentionCount": 7}` | scheduled encrypted backups (§11) |
| `oidc` | disabled | OIDC single sign-on — issuer, client, claims, role mapping (§15); secret encrypted at rest |
| `ldap` | disabled | LDAP / Active Directory sign-in — server, bind account, filter, role mapping (§15); bind password encrypted at rest |
| `audit_forward` | disabled | forward audit events to a syslog or HTTP SIEM endpoint (§16) |

The **Settings → Branding** card edits the application name in the UI; the change
takes effect immediately (no rebuild) and is served publicly so the login screen
reflects it.

Per-IP rate limits and session/cert TTLs are environment variables
(`FLEET_RATE_LIMIT_*`, `FLEET_SESSION_*`, `FLEET_*_TTL`) — see
[deployment.md](./deployment.md).

### Time zone

**Settings → Time zone** (`System.Configure`) is an IANA time-zone picker that
drives **how all timestamps are displayed** *and* **how schedule clock-times are
interpreted**. It pre-fills the browser's detected zone. Saving recomputes the
**next-run** time of every enabled schedule (§8).

## 10. Notifications

**Settings → Notifications** (`System.Configure`) delivers outbound alerts. Both
channels are **off until enabled**:

- **Email** — a generic SMTP relay: host, port, security (`STARTTLS` / `TLS` /
  `none`), username, password, from, and to addresses. The SMTP **password is
  encrypted at rest** and never returned by the API.
- **Webhook** — posts JSON to a URL; **format** shapes the body for generic JSON,
  Slack/Mattermost, Discord, or **Microsoft Teams** (a MessageCard payload).

A per-event **routing matrix** decides which events go to which channel. Events:

- Host went offline
- Host recovered
- Access request pending approval
- Security scan found failures
- Playbook run failed
- Vulnerability (CVE) findings (§21)
- Scheduled compliance report ready (`report.scheduled`, §20)
- Fleet-health digest (`fleet.digest`, §22)
- CA key due for rotation (§13)

A **throttle** (minutes) suppresses repeats of the same event (e.g. a flapping
host). Each channel has a **Send test** button.

### Incident channels (PagerDuty & Opsgenie)

Two integrations **page on-call** instead of posting per event:

- **PagerDuty** (Events API v2) — a **routing/integration key** (stored
  **encrypted**, write-only).
- **Opsgenie** (Alerts API) — an **API key** (encrypted, write-only) and a **US or
  EU** region.

Unlike the per-event routing matrix, these are **severity-gated**: each fires on
**any** event at or above a configurable **minimum severity** — *errors only*,
*warnings + errors*, or *everything* — which keeps info-level traffic (digests,
scheduled reports) from paging. Severity maps: `error` → PagerDuty **critical** /
Opsgenie **P1**, `warning` → **warning** / **P3**, `info` → **info** / **P5**.
Configure enable, key, region, and minimum severity under **Settings →
Notifications**; each has its own **Send test**. (No new endpoints — they are part
of the `notifications` settings.)

## 11. Backup & restore

**Settings → Backup & Restore** (`System.Configure`) produces **encrypted logical
database backups**: `pg_dump` piped through `openssl` (AES-256-CBC, PBKDF2) into
the backup directory.

- **Back up now**, then **list** and **download** stored backups (encrypted, or a
  **plaintext** download).
- Optional **scheduled backups**: enable, set the **interval (hours)** and a
  **retention count** (older backups are pruned).
- **Restore** is an offline one-liner shown in the UI:
  `openssl enc -d … | psql`.

| Variable | Default / behavior |
|----------|--------------------|
| `FLEET_BACKUP_DIR` | `/var/lib/fleet/backups` — **map to off-host storage** |
| `FLEET_BACKUP_PASSPHRASE` | encrypts backups; **falls back to `FLEET_CA_PASSPHRASE`**. Keep a copy **OFF the server** — without it, backups are unrecoverable |

> The authoritative recovery + break-glass runbook is
> [break-glass.md](./break-glass.md). Read it before you need it.

## 12. Audit & monitoring

- **Audit log:** `GET /api/v1/audit` (filter by `action`, `actor`). Every state
  change is recorded in a hash-chained log.
- **Integrity check:** `GET /api/v1/audit/verify` → `{"intact":true,"brokenAtSeq":0}`.
  Run this periodically; a non-zero `brokenAtSeq` indicates tampering.
- **Export:** `GET /api/v1/audit/export` streams the full chain for archival.
- **Metrics:** scrape `GET /metrics` (Prometheus). See [Security Guide](./security-guide.md).

## 13. Certificates

Manage the CA and certificate lifecycle (`Certificate.Manage`) under
`/api/v1/certificates`: list issued certs, rotate the CA, revoke a serial, and
fetch the KRL. Details in [certificate-lifecycle.md](./certificate-lifecycle.md).

### CA key rotation reminder

The SSH CA key never auto-expires. To nudge you to rotate it, the certificate
renewal loop checks the active CA key's age **hourly**; once it exceeds
`FLEET_CA_ROTATE_AFTER` (default **365 days**) it raises a **"CA key due for
rotation"** notification — a routable event in **Settings → Notifications**
(§10), throttled to roughly weekly so it nudges rather than spams. Rotate the CA
with `fleetctl rotate-ca` or from the **Certificates** page. Set
`FLEET_CA_ROTATE_AFTER=0` to disable the reminder. The CA key's age is also shown
on the **System Health** page (§17).

## 14. Routine operations

| Task | Command / endpoint |
|------|--------------------|
| Tail logs | `make logs` |
| Restart stack | `make down && make up` |
| Stop (keep data) | `make down` |
| Wipe everything | `make clean` (**destroys volumes**) |
| Health / readiness | `GET /health`, `GET /ready` |
| System Health (components + jobs) | `GET /api/v1/system/health` (`System.Configure`) — the **Health** page (§17) |
| Verify audit chain | `GET /api/v1/audit/verify` |

For backups see §11; for restore, recovery, and break-glass procedures see
[break-glass.md](./break-glass.md) and [Disaster Recovery](./disaster-recovery.md).

## 15. Single sign-on (SSO)

Fleet Terminal can authenticate users against an external identity provider via
**OIDC**, **SAML 2.0**, or **LDAP / Active Directory**, in addition to local
accounts, and can accept **SCIM 2.0** provisioning. Every user carries an
**`auth_source`** (`local` | `oidc` | `saml` | `ldap`); accounts backed by an
external directory **cannot use a local password**. All integrations are
configured by `System.Configure` holders.

### OIDC (Okta, Azure AD, Google Workspace, Keycloak, Authentik, …)

**Settings → Single sign-on (OIDC)**. Configure:

- **Issuer URL**, **Client ID**, and **Client secret** (write-only — **encrypted
  at rest** and never returned by the API).
- **Scopes** (default `openid` / `profile` / `email`).
- **Username / email / groups claims** (defaults `preferred_username`, `email`,
  `groups`).
- **Default role** for newly provisioned users, an **auto-provision** toggle,
  **group → role mappings** (one per line, `idpGroup=FleetRole`), and the login
  **button text**.

Set your IdP's redirect / callback URL to **`<PublicURL>/api/v1/auth/oidc/callback`**.
Fleet uses the **authorization-code flow with PKCE** and verifies the ID token
against the provider's **JWKS**. On first login it finds the user by **username,
then email**; if not found and auto-provision is on, it creates the account
(`auth_source = oidc`) with the default role. **Group → role mappings are applied
additively** on top of the default role, then a normal Fleet session is issued.
When OIDC is enabled the login page shows a **"Sign in with SSO"** button.

| Action | Endpoint |
|--------|----------|
| Read / save OIDC config | `GET/PUT /api/v1/auth/oidc/config` (`System.Configure`) |
| Provider status (drives the button) | `GET /api/v1/auth/oidc/status` |
| Begin login / callback | `GET /api/v1/auth/oidc/login`, `GET /api/v1/auth/oidc/callback` |

### SAML 2.0 (Okta, Azure AD / Entra ID, OneLogin, ADFS, …)

**Settings → Single sign-on (SAML)**. The card shows the three values your IdP
needs to register Fleet as a Service Provider:

- **ACS (Reply) URL** — `<PublicURL>/api/v1/auth/saml/acs`
- **SP Entity ID / Audience** — defaults to `<PublicURL>/api/v1/auth/saml/metadata`
- **SP metadata** — `<PublicURL>/api/v1/auth/saml/metadata` (importable by most IdPs)

Then configure the IdP side in Fleet:

- **IdP Entity ID (issuer)**, **IdP SSO URL** (HTTP-Redirect binding), and the
  **IdP signing certificate** (PEM or base64 — public, used to verify assertion
  signatures).
- **Attribute mapping**: username (blank = use the assertion **NameID**), email,
  display-name, and groups attributes.
- **Default role**, the **auto-provision** toggle, **group → role mappings**, and
  the login **button text**.

Fleet validates the IdP-signed assertion's **signature, audience, and time
bounds** before trusting it, then finds the user by **username, then email**;
if not found and auto-provision is on, it creates the account
(`auth_source = saml`) with the default role — **group → role mappings apply
additively**. Both **SP-initiated** (the "Sign in with SAML" button) and
**IdP-initiated** (an Okta/Azure app tile that POSTs to the ACS) flows work.
Because the assertion is signed by the trusted IdP, its attributes are
authoritative — no separate email-verification gate is needed. AuthnRequests are
sent **unsigned** (baseline); the IdP must sign its assertions.

> **Auto-provision off?** Users can still sign in via SAML, but only if the
> account already exists (created by an admin or by **SCIM**, below). This is the
> tighter posture: no account exists until the IdP explicitly provisions it.

| Action | Endpoint |
|--------|----------|
| Read / save SAML config | `GET/PUT /api/v1/auth/saml/config` (`System.Configure`) |
| Provider status (drives the button) | `GET /api/v1/auth/saml/status` |
| Begin login / ACS / metadata | `GET /api/v1/auth/saml/login`, `POST /api/v1/auth/saml/acs`, `GET /api/v1/auth/saml/metadata` |

### SCIM 2.0 provisioning (lifecycle automation)

**Settings → Provisioning (SCIM 2.0)**. SCIM lets your IdP **create, update, and
deprovision** Fleet accounts automatically — most importantly, it **disables an
account the moment a user is removed in the IdP**, before they would ever attempt
to sign in. It pairs with SAML: SCIM manages the account lifecycle, SAML
authenticates the login.

- **Issue token** generates a bearer token (prefix `scim_`) shown **exactly
  once** — store it in your IdP's SCIM connector. Only its hash is kept.
- Point the IdP's SCIM **base URL** at `<PublicURL>/api/v1/scim/v2`.
- **Default role** for provisioned users and the **sign-in method**
  (`auth_source`) new accounts receive — set this to **SAML** (default) when
  pairing with SAML SSO, or OIDC/LDAP to match your login method.
- **Revoke token** stops provisioning immediately.

Supported: **Users** create / read / replace / **PATCH** (the `active=false`
deprovision signal) / delete, and the `userName eq` filter; plus the
ServiceProviderConfig / ResourceTypes / Schemas discovery endpoints. Disabling or
deprovisioning a user **immediately ends their live sessions and destroys their
SSH credentials**. All provisioning actions are **audited**.

| Action | Endpoint |
|--------|----------|
| Read / save SCIM config | `GET/PUT /api/v1/scim/config` (`System.Configure`) |
| Issue / revoke provisioning token | `POST/DELETE /api/v1/scim/token` (`System.Configure`) |
| SCIM 2.0 protocol (Users, discovery) | `/api/v1/scim/v2/*` (SCIM bearer token) |

### LDAP / Active Directory

**Settings → LDAP / Active Directory**. Configure:

- **Server URL** (`ldap://` or `ldaps://`) and an optional **StartTLS** toggle.
- **Bind DN** + **bind password** — a read-only **service account** (the bind
  password is **encrypted at rest**).
- **Base DN** and a **user filter** (`%s` = the entered username, e.g.
  `(sAMAccountName=%s)`).
- **Username / email / display-name / groups** attributes.
- **Default role**, an **auto-provision** toggle, and **group → role mappings**
  (`GroupCN=FleetRole`).

Directory users sign in on the **normal sign-in form** with their directory
credentials — the login flow **falls back to LDAP when local auth fails**. The
service account looks the user up, then the password is verified by **binding as
the user's own DN**; the account is found-or-provisioned (`auth_source = ldap`)
and **group → role mappings are matched on each group's CN**.

| Action | Endpoint |
|--------|----------|
| Read / save LDAP config | `GET/PUT /api/v1/auth/ldap/config` (`System.Configure`) |

## 16. Audit forwarding (SIEM)

**Settings → Audit forwarding (SIEM)** (`System.Configure`) forwards **every**
audit event to an external collector. It is **best-effort and off by default** —
the in-app **hash-chained audit log remains the system of record** (§12); a failed
forward is logged and never blocks the action.

| Field | Values |
|-------|--------|
| `enabled` | on / off |
| `type` | `syslog` or `http` |
| `address` | `host:port` for syslog, a full URL for HTTP |
| `protocol` | `udp` or `tcp` (syslog only) |

- **syslog** emits **RFC 5424** messages over UDP or TCP.
- **http** POSTs each event as a **JSON** body to the endpoint.

Use the **Send test event** button to confirm connectivity.

| Action | Endpoint |
|--------|----------|
| Read / save config | `GET/PUT /api/v1/audit/forwarding` (`System.Configure`) |
| Send a test event | `POST /api/v1/audit/forwarding/test` (`System.Configure`) |

## 17. System Health page

The **Health** sidebar page (`System.Configure`) shows the **live status** of the
deployment and **auto-refreshes**. Each component reports **ok / warn / error**,
and the page rolls them up into an overall status. It covers:

- **Database** connectivity.
- **Certificate authority** — whether an active CA key is loaded, and its **age**
  (flagged once past `FLEET_CA_ROTATE_AFTER`; see §13).
- **Jump host** reachability.
- **Ansible runner** sidecar reachability (§7).
- **Backups** — count stored and the **age of the latest** (§11).
- **Every background job** — monitor, certificate renewal, the approval reaper,
  retention, and KRL distribution — with each job's last run, run count, and last
  error.

It is served by `GET /api/v1/system/health`.

## 18. Service accounts & API tokens

A **service account** is a non-human identity for automation (CI/CD, IaC,
monitoring): a user record flagged `is_service_account` with **no password**, so it
**cannot log in interactively or via SSO**. It carries **roles** (permissions) and
**group memberships** (host access) exactly like a human user, survives employee
turnover, and appears in the audit log under its own username as the actor.

Manage them from the **Service Accounts** page (left nav, gated
**`ServiceAccount.Manage`** — seeded to Super Administrator and Administrator).
Create one with a name plus its **roles** and **groups**; enable/disable or delete
it; and manage its tokens.

> **Privilege-escalation guard:** a manager may only assign a service account roles
> whose permissions the manager **themselves holds** (super admins are
> unrestricted). You cannot mint an account more powerful than yourself.

### API tokens

A token authenticates a service account to the **REST API**:

- Format `flt_<random>`, sent as `Authorization: Bearer flt_…`. `RequireAuth` routes
  any `flt_`-prefixed bearer to token auth; JWT session tokens are unaffected.
- Stored **only as a SHA-256 hash** — the plaintext **secret is shown once** at
  creation (copy it then). Optional **expiry** (30 / 90 / 365 days or never),
  **revocable**, with a throttled `last_used_at` (≤ 1/min).
- A token is **never implicitly super-admin** — it carries exactly its account's
  roles and groups.
- **REST-only:** a token **cannot open the terminal / SFTP WebSocket** (those need a
  session-bound SSH credential). Use it for API automation, not interactive
  sessions.

| Action | Endpoint (all `ServiceAccount.Manage`) |
|--------|----------------------------------------|
| List service accounts | `GET /service-accounts` (roles, groups, token count, last used) |
| Create | `POST /service-accounts` `{username, displayName, roleIds[], groupIds[]}` |
| Edit / enable / disable | `PATCH /service-accounts/{id}` `{displayName?, disabled?, roleIds?, groupIds?}` |
| Delete | `DELETE /service-accounts/{id}` |
| List tokens | `GET /service-accounts/{id}/tokens` |
| Issue a token | `POST /service-accounts/{id}/tokens` `{name, expiresInDays}` → `secret` (once) |
| Revoke a token | `DELETE /service-accounts/{id}/tokens/{tokenId}` |

> Scope service accounts **least-privilege** — only the roles and groups the
> automation needs. Revoke a token immediately if it may be exposed; revocation is
> instant.

## 18b. Credential vault

The **Credentials** page (a `Credential.View` or `Credential.Manage` holder sees it)
stores static credentials — **passwords, SSH keys, API keys** — for systems that
can't use Fleet's ephemeral certificates (network gear, appliances, databases,
legacy hosts). Secret material is **encrypted at rest** with secretbox under a
dedicated **`FLEET_VAULT_PASSPHRASE`** (required in production, must differ from the
CA passphrase — see the Deployment guide).

- **Store** a credential with a name, folder, type, username, and target; the secret
  value is sealed server-side and never stored in plaintext.
- **Reveal** returns the plaintext — gated by `Credential.View` (or `Credential.Manage`)
  plus access to that secret, and **always written to the audit log**.
- **Grants** delegate access to a specific credential to a user or group at
  **view** (reveal), **use** (inject — see below), or **manage** level, without
  giving them the vault-wide `Credential.Manage` permission. Administrators hold
  `Credential.Manage` (all credentials); Operators get view/use/rotate; **Auditors
  are deliberately excluded from reveal**.
- **Versioning:** editing a credential's value stores a new version (rotation
  history) while keeping the metadata.

**Rotation.** Editing a credential's value always stores a new **version** (history).
For a **password** credential attached to a host, the **Rotate** action (needs
`Credential.Rotate`) rotates it automatically: Fleet connects to the host with the
current password, sets a new random one via `chpasswd`, verifies the new login, and
stores it — the operator never sees either value. The vault is kept consistent with
the host: if the host change fails, the stored value is reverted. This requires the
login account to have **passwordless `sudo chpasswd`** on the host, and it runs
on-demand (a user's live session authenticates the path). Validate it against a test
host before relying on it in production. (Automated password change over SSH is
inherently environment-specific; SSH-key and scheduled rotation are future work.)

**Check-out & approval.** Each credential has an **access policy**:

- **Open** (default): reveal / inject directly per grants.
- **Check-out required:** the credential can't be revealed or injected until the
  caller **checks it out** for a time-boxed window (self-service; tracked and audited).
- **Approval required:** checking out first needs a **`Credential.Approve` holder**
  (not the requester) to approve — the classic four-eyes control for high-value
  credentials. Approvers see a "Check-outs awaiting your approval" inbox on the
  Credentials page.

While a check-out is active the credential works normally (reveal on the page, or
injection when connecting to a host that uses it); once it expires or is checked in,
access ends and a fresh check-out (or approval) is required. Every request, approval,
denial, and check-in is audited.

**Credential injection (connect without seeing the secret).** On a host's edit form,
set **Authentication** to **Vault credential — password** or **— SSH key** and pick a
credential. When anyone connects (terminal or SFTP) to that host, Fleet resolves the
credential, decrypts it **in memory**, and authenticates the SSH connection with it —
the operator **never sees the secret**, and it never reaches the browser. Sessions
opened this way are audited (`session.credential_injected`). Attaching a credential to
a host requires `Host.Edit` plus access to that credential (`Credential.Manage`, or a
`use`/`manage` grant), so a host editor can't bind a secret they couldn't use. Hosts
default to Fleet certificate authentication; use vaulted auth for appliances, network
gear, and legacy systems that can't accept Fleet's ephemeral certificates.

## 18c. Windows desktops (RDP)

Fleet brokers **RDP (Windows desktop)** sessions to the browser through the bundled
**guacd** sidecar (Apache Guacamole daemon), so operators reach a full remote desktop
from the same UI as SSH — no local RDP client, no direct network route to the host.

**How it reaches the host.** The backend tunnels the target's RDP port **through the
jump host** (the same path as SSH) and exposes it to guacd as an ephemeral local
proxy. guacd therefore only ever connects back to the backend — it needs **no route to
managed hosts**, and RDP traffic still rides the WireGuard overlay / jump hop. Two
settings wire the pair (defaults match the bundled compose file):
`FLEET_GUACD_ADDR` (where the backend reaches guacd, default `guacd:4822`) and
`FLEET_RDP_PROXY_HOST` (how guacd reaches the backend, default `backend`).

**Configure an RDP host.** On the host form set **Protocol** to **RDP (Windows
desktop)** and the **RDP Port** (default `3389`). RDP has no Fleet-certificate mode:
**Authentication** must be a **Vault credential — password**, so the Windows account
password is stored in the vault and **injected into guacd in memory** — the operator
never sees it and it never reaches the browser. Attaching the credential enforces the
same `Host.Edit` + credential-access checks as SSH injection, and if the credential
has a check-out policy the operator must hold an active check-out to connect.

**Connect.** An RDP host shows a **desktop** action (instead of terminal/SFTP) that
opens the live desktop in a new tab, gated by `Host.Connect` and the usual per-host
access checks. Each connection is audited (`session.rdp_start`). Clipboard, drive
redirection, multi-monitor, and session recording for RDP are not in this release.

## 19. Live session shadowing

**Session shadowing** is read-only, real-time viewing of an **active** terminal
session — four-eyes oversight of privileged access. The watcher sees the operator's
exact output at the operator's terminal size but **sends no input** (strictly
one-way). It is distinct from recording/replay, which is after-the-fact.

- Permission: **`Session.Watch`** (seeded to Super Administrator, Administrator, and
  Auditor).
- From **Session Replay**, active sessions expose a **Watch live** action that opens
  a full-screen, read-only xterm viewer rendered at the operator's dimensions.
- Watching is **itself audited** (`session.watch` — who watched which session, and
  when), so oversight is accountable.

| Action | Endpoint |
|--------|----------|
| Watch a live session | `GET /sessions/{id}/watch` — WebSocket, auth via `?token=` (like the terminal WS); `{id}` is the SSH-session id |

## 20. Compliance reports

The **Reports** page (left nav, gated **`Audit.View`**) produces **on-demand CSV
exports** over a `from`/`to` date range — org-wide auditor evidence:

| Export | Contents |
|--------|----------|
| `GET /reports/access.csv` | SSH sessions — user, host, client IP, start/end, status, bytes |
| `GET /reports/audit.csv` | audit events with full (untruncated) detail |
| `GET /reports/certificates.csv` | SSH cert issuance — serial, kind, subject, principals, validity, revocation |
| `GET /reports/scans.csv` | OpenSCAP scan posture over time |
| `GET /reports/vulnerabilities.csv` | CVE findings — host, package, installed/fixed, severity, CVSS |

Query with `?from=YYYY-MM-DD&to=YYYY-MM-DD` (or RFC3339); default is the last 30
days, and `to` is an **exclusive** end-of-day. All are gated `Audit.View`.

### Scheduled report delivery

Fleet can deliver reports automatically — **weekly or monthly**, at a chosen day and
hour, covering a lookback window — as **CSV email attachments** through the
notification channels. Configure it on the **Scheduled compliance reports** settings
card; delivery emits a `report.scheduled` event, so **route that event to Email**
under Notifications (§10) to receive the attachments.

| Action | Endpoint |
|--------|----------|
| Read / save the schedule | `GET/PUT /report-schedule` (`System.Configure`) |
| Send one now | `POST /report-schedule/send` (`System.Configure`) |

> Email attachments are multipart; the **webhook channel ignores attachments** and
> sends only the summary body, so scheduled reports must go to **Email**.

## 21. Vulnerability scanning (CVE)

CVE scanning is **distinct from OpenSCAP compliance scans**: it matches a host's
**installed packages** against a CVE database and reports findings with **CVSS
scores**.

**Architecture.** A **grype-scanner sidecar** (Anchore Grype + the CVE database, its
own container — compose service `grype-scanner`, `FLEET_GRYPE_SCANNER_URL` default
`http://grype-scanner:8000`) does the matching. The backend dials the host through
the jump host, **tars its package databases** (`/etc/os-release` +
`/var/lib/dpkg/status` or `/var/lib/rpm`) over SSH, and posts them to the sidecar —
**nothing is installed on the managed hosts**. CVSS is enriched from Grype's related
NVD records, so distro sources (Debian/Ubuntu) that carry severity but not scores
still get a numeric CVSS.

Each finding records the CVE id, package, installed vs. fixed version, severity,
CVSS score and vector, data source, and description; each scan row records
per-severity counts and the max CVSS.

- Scan a **host** or a **whole group**, **on demand** or on a **schedule** (the
  `vulnscan` schedule kind, alongside scan/playbook — §8). Findings are
  **severity-gated notified** (§10) and audited; stale scans are reconciled on
  restart.
- The **Vulnerabilities** page (nav, gated **`Host.Scan`**) shows a **fleet roll-up**
  — max CVSS plus critical/high/medium counts per host — with a drill-in findings
  table and live progress. CSV export is on **Reports** (§20).

| Action | Endpoint |
|--------|----------|
| Start a scan | `POST /vuln-scans` `{hostId}` or `{groupId}` → `{scanIds:[…]}` (`Host.Scan`) |
| Recent scans for a host | `GET /vuln-scans?hostId=` |
| Fleet roll-up | `GET /vuln-scans/latest` (latest completed per host) |
| Scan + findings | `GET /vuln-scans/{id}` |

### CVE database management

The scanner needs a CVE database, managed on the Vulnerabilities page (gated
**`System.Configure`**). The current **DB build date** is shown, and the DB persists
in the **`grype-db`** volume; Grype's DB age-validation is disabled, so a
self-managed DB of any age is usable.

- **Update online** — pulls a fresh Grype DB (needs the backend/sidecar to have
  **internet access**).
- **Import offline** — upload a **pre-downloaded Grype DB archive** for
  **air-gapped** deployments. Download the archive on a connected machine, then
  import it here.

| Action | Endpoint |
|--------|----------|
| DB status | `GET /vuln-scans/db` |
| Online update | `POST /vuln-scans/db/update` (`System.Configure`) |
| Offline import | `POST /vuln-scans/db/import` (`System.Configure`) — archive upload |

## 22. Fleet insights & health digests

The local-LLM **Ask AI** assistant (§9, `assistant` setting) is backed by two
admin-facing features:

- **Fleet insights** — an explainable engine (no ML) derives issues from host status
  and metric history: offline hosts, low / critically-low disk, high memory/load,
  pending security updates, and a **disk-runway projection** (days-to-full with a
  confidence level from the trend fit). It surfaces as the Dashboard **"Needs
  attention"** card and a `GET /insights` endpoint (scoped to the caller's
  accessible hosts).
- **Scheduled health digests** — a **daily or weekly** fleet-health digest built from
  the same insights and delivered via notifications (a `fleet.digest` event — route
  it to a channel under §10). Configure it on the **Fleet-health digest** settings
  card.

| Action | Endpoint |
|--------|----------|
| Read / save the digest schedule | `GET/PUT /digest` (`System.Configure`) |
| Preview the current digest | `GET /digest/preview` (`System.Configure`) |
| Send one now | `POST /digest/send` (`System.Configure`) |
