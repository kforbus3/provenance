# Changelog

Notable changes to Fleet Terminal, newest first. Dates are release dates. Database
schema migrations apply automatically on startup; deploy notes call out anything else.

---

## v0.55.4 — Generic org placeholder in module paths

The Go SDK and Terraform provider module paths, and the clone/`go get`/`go install`
examples in the docs, now use a generic `your-org` placeholder
(`github.com/your-org/Fleet-Terminal/...`) instead of a specific GitHub account.

- **Action for SDK / Terraform users:** substitute your own GitHub org in the import
  path and provider source (or use a local `replace` directive, as the bundled
  Terraform provider already does against `../sdk`). Building from this repo is
  unaffected — the local replace directive resolves the SDK without a network fetch.

## v0.55.3 — Live host status on the terminal view

Extends v0.55.2 to the in-terminal view. The terminal header now shows the host's
**online/offline** status as its own chip (next to the connection-status chip), and it
updates live — driven by the same app-wide `host.status` subscription, with a 30-second
scheduled refetch as a fallback. Invalidation now also refreshes the single-host detail
query, so the file browser and host-details dialog stay current too.

## v0.55.2 — Live host status across the UI

Host online/offline changes now show up on their own — no manual page refresh.

- The app already broadcasts `host.status` on every monitor probe over a WebSocket, but
  only the Dashboard consumed it. That subscription is now **app-wide** (in the shell
  that's mounted on every page), so the **Terminals** launcher, the **Hosts** grid, and
  the **Dashboard** all reflect a host coming online/offline within seconds — from a
  single shared connection. Previously the Terminals and Hosts lists never updated until
  you reloaded.
- Added a **30-second scheduled refetch** to the Terminals and Hosts lists as a fallback,
  so status stays current even if the events socket is briefly disconnected.

## v0.55.1 — Accurate pending updates on RHEL-family hosts

Follows up v0.54.1 (which fixed the Debian/Ubuntu path) with the RHEL/dnf/yum side.

- **Per-package security flags are now correct on dnf hosts.** The dnf path previously
  hard-coded every pending package to *non-security* in the package list (only the
  aggregate count tried, via `updateinfo`, to reflect security updates) — so on RHEL,
  Rocky, Alma, and Fedora hosts no individual package was ever shown as a security
  update. Collection now uses `dnf repoquery --upgrades --latest-limit 1` for a clean,
  de-duplicated one-row-per-package list and `--security` to flag each security update,
  so the per-package flags and the security count agree.
- **More robust parsing.** repoquery's machine-readable output avoids the header/line-wrap
  and "Obsoleting Packages" pitfalls of scraping `dnf check-update` columns; a
  check-update fallback covers minimal installs without repoquery. The yum path (RHEL 7)
  gains the same per-package security flagging via `yum --security` when available.
- Validated against a real Rocky Linux 9 host (108 pending, 56 security — counts and
  per-package flags consistent, matching `dnf check-update`). Counts refresh on the next
  hourly inventory sweep. Like the apt path, collection reads cached metadata (kept fresh
  by `dnf-makecache.timer`), so it stays cheap and adds no network load.

## v0.55.0 — Cross-instance live session shadowing (HA)

Closes the last HA gap: **live session shadowing now works across instances.** Watching
an in-progress session (`Session.Watch`) previously only worked if the watcher happened
to land on the same instance as the session's PTY; otherwise the watcher saw nothing.

- When a watcher attaches to a session another instance owns, it announces interest over
  the existing Postgres LISTEN/NOTIFY backplane, and the owning instance mirrors that
  session's live output/resize frames to peers — **only while a remote watcher is
  attached**, so an unwatched session adds zero backplane traffic.
- Frames are chunked to fit the NOTIFY payload limit and relayed on a dedicated,
  non-blocking path, so shadowing never slows the operator's terminal; under a burst a
  remote watcher drops frames rather than stalling the session (same policy as a local
  slow watcher).
- No new infrastructure or configuration — it rides the backplane Fleet already uses, and
  is inert in a single-instance deployment.
- The HA test stack (`deploy/compose/docker-compose.ha.yml`) is now self-contained: it
  pins its two backends to its own Postgres single-tenant, so it runs as-shipped
  regardless of the production `FLEET_DATABASE_URL` / multi-tenancy in your `.env`.

Verified live: leader-kill failover, ownership reconciliation (dead-owner rows fail while
live peers are spared), and — via two real backends over one Postgres — cross-instance
events, terminate, and the shadow subscribe + chunked-frame relay all round-trip.

## v0.54.1 — Pending-updates accuracy + Ask-AI timezone fixes

Three fixes to how host updates are collected and how the assistant reports times.

- **Pending updates now match `apt update`.** The monitor collected pending updates
  with `apt-get -s upgrade`, which silently holds back packages that need new
  dependencies and Ubuntu **phased updates** — so hosts whose only pending updates
  were phased/kept-back showed *nothing* pending even though `apt update` listed them
  (and since security updates are rarely phased, a host often surfaced its security
  updates while all its regular updates stayed invisible). Collection now uses
  `apt list --upgradable`, which enumerates every upgradable package exactly as
  `apt update` reports it. Host Details, the dashboard, and Ask AI now reflect the
  real update posture; counts refresh on the next inventory sweep (hourly).
- **Ask AI reports schedule times in your timezone.** The assistant rendered schedule
  and other times in UTC and left recurrences like "daily at 03:00" unlabeled, so it
  would say a 03:00-Eastern schedule runs at "03:00 UTC". It now knows the configured
  display timezone, labels recurrences with the zone ("daily at 03:00 EDT"), and
  reports times in that zone.

## v0.54.0 — Federation site key rotation

Completes federation key lifecycle: a **site can rotate its own identity key** in
place, mirroring the existing hub-key rotation, with no re-enrollment and no link
downtime.

- **Site-initiated rotation** (`POST /api/v1/federation/site/rotate-key`,
  `System.Configure`). The site generates a new keypair and, over its
  already-authenticated link, sends the new public key **signed by its current key**.
  The hub verifies that against the site's active key and stages the new key as
  *pending* — leaving the current key in force — then **promotes** it to active on the
  site's next reconnect with the new key. The hub accepts both keys during the overlap,
  so a crash or drop mid-rotation never locks a site out.
- **Prompt reconnect.** A site reacts to its link closing immediately (rather than at
  the next push tick), so a rotation promotes within seconds.
- **Transport honesty.** `FLEET_FEDERATION_TRANSPORT=wireguard` no longer implies a
  distinct wire protocol. The federation protocol is always WSS (outbound TLS 443 +
  Ed25519 auth); `wireguard` documents that the WSS link rides a WireGuard/VPN underlay
  (point `FLEET_HUB_URL` at the overlay address). Both values run identical code.
- Uses the pre-existing `pending_public_key` column (no new migration). See
  docs/federation.md ("Key rotation", "Transport").

## v0.53.0 — Federation site-as-tenant

A multi-tenant **hub** now isolates federated sites per tenant, completing the MSP shape where one
hub serves many provider customers. Off by default and a no-op unless multi-tenancy is enabled.

- **A site belongs to the tenant that minted its join token.** The site, its aggregated read-cache
  (inventory, sessions, scans, schedules, playbook runs, SFTP transfers), and its sync state are all
  owned by that tenant and enforced by Postgres row-level security.
- **Everything hub-side is tenant-scoped.** The Sites list, the top-bar site selector, the aggregated
  cross-site inventory and dashboards, and the proxy all show and reach only the acting tenant's own
  sites. A cross-tenant site id resolves to *not found* — the proxy (browser terminals, SFTP, every
  management page) can never reach another customer's infrastructure.
- **No change for single-tenant / non-multi-tenant hubs.** Every site simply belongs to the default
  tenant, exactly as in v0.52.0. Standalone instances are unaffected.
- Migration `0062` adds tenant scoping + RLS to the federation and cache tables. See
  docs/federation.md ("Federation and multi-tenancy").

## v0.52.0 — Multi-site federation

Turn one Fleet instance into a **hub** — a single pane of glass over many independent **site**
instances, each a full autonomous Fleet stack on its own network. Opt-in and **off by default**
(`FLEET_MODE=standalone`): a standalone instance builds and mounts none of it and is unchanged.

- **Site-initiated tunnels.** Sites need no inbound reachability — each dials the hub over a single
  outbound WSS connection (yamux-multiplexed); the hub never routes back into a site.
- **Ed25519 trust, no shared secrets.** The hub generates a federation identity on first boot
  (encrypted at rest with `FLEET_CA_PASSPHRASE`); a site generates its own keypair at join and pins
  the hub's key fingerprint (MITM defense). Every hub→site action carries a short-lived, hub-signed
  **acting-user assertion** bound to one exact request (`sha256(method+path+body)` + single-use nonce).
- **Single pane of glass.** On a hub, a top-bar **site selector** points the *entire* UI at a chosen
  site — host list, terminals, SFTP, databases, Kubernetes, scans, playbooks, schedules, audit — all
  transparently proxied to the site's own unmodified API (a request interceptor rewrites `/api/v1/*`).
- **Autonomy + trust boundaries.** Each site runs proxied requests through its **own** handlers under a
  site-local shadow user, so it enforces its own RBAC/[access policies](access-policies.md) and keeps
  its own **authoritative** audit hash-chain (the hub keeps a linked copy) — the hub is an
  authorization initiator, never a bypass. A site keeps working if the hub or WAN is down.
- New `internal/federation` package, `Federation.Manage` permission, **Sites** page, and migrations
  `0060`/`0061`. Verified end-to-end with a live hub+site (join, link, cross-site proxy, revoke). See
  docs/federation.md — including how federation composes with multi-tenancy.

## v0.51.0 — ITSM two-way sync

The ITSM integration (v0.48.0) now writes the **decision back** to the linked ticket: when an access
request is approved or denied, Fleet posts a ServiceNow *work note* or a Jira *comment* recording the
outcome, who decided, and the granted duration (audited as `approval.ticket_update`). Best-effort, so
a decision is never blocked on the ITSM. Closing/transitioning the ticket remains the ITSM workflow's
job. Verified end-to-end (request → ticket opened → approval → comment written back). See docs/itsm.md.

## v0.50.0 — External secrets: AWS Secrets Manager

The external secrets manager (vault-of-record, v0.47.0) now supports **AWS Secrets Manager**
alongside HashiCorp Vault KV. Back a vault credential with an AWS secret (name or ARN, optionally
`#field` to extract one key from a JSON secret); Fleet fetches it on demand via a SigV4-signed
`GetSecretValue` — no AWS SDK, and no local copy is stored. Configure with `FLEET_EXTSECRET_AWS_*`
(an endpoint override supports emulators). The SigV4 signer is now shared (`internal/awssig`)
between AWS KMS and Secrets Manager. Verified end-to-end against LocalStack. See
docs/external-secrets.md.

## v0.49.0 — Database broker: MongoDB

The database broker now speaks **MongoDB** alongside PostgreSQL/MySQL/MariaDB/SQL Server. Because
MongoDB is document-oriented, its console takes a **MongoDB command document as JSON** (e.g.
`{ "find": "users", "limit": 10 }`) and returns the result as formatted JSON, with the same
vaulted-credential injection and `db.query` auditing as the SQL engines.

- The MongoDB driver opens several connections, so each driver dial gets its **own fresh jump
  tunnel** (rather than the single shared tunnel the SQL engines use); the tunnels are wrapped to
  tolerate the driver's deadline calls (SSH channels don't support them). This hardening also covers
  the MySQL/SQL Server drivers over the real jump tunnel.
- Migration `0059` widens the engine constraint; the Databases page adds MongoDB (default port
  27017) and a JSON-command console. Verified end-to-end against a live MongoDB (`listDatabases` and
  `find` through the broker with a vaulted credential). See docs/database-broker.md.

## v0.48.0 — ITSM integration (ServiceNow / Jira)

Tie privileged access to change management. When enabled, Fleet opens a **change/incident ticket**
in ServiceNow or Jira for each just-in-time access request and attaches the ticket reference to the
approval, so every grant carries a change record.

- Best-effort and non-blocking: if the ITSM is unreachable the access request still proceeds
  (failures logged, successes audited as `approval.ticket`). The ticket reference and link are
  included in the approval notification.
- Configure under Settings → Integrations (`System.Configure`): provider, base URL, user, token,
  and table/project. The token is sealed at rest and never returned by the API; a **Test
  connection** button validates credentials without creating a ticket.
- New `internal/itsm` (ServiceNow + Jira clients, stdlib HTTP, no SDK) and `itsm/config` +
  `GET/PUT /itsm/config`, `POST /itsm/test`. Verified end-to-end (a request opened a ServiceNow
  ticket and attached its reference). See docs/itsm.md.

## v0.47.0 — External secrets manager (vault-of-record)

A vault credential can now be **external-backed**: instead of Fleet storing the secret material, the
credential references it in an external secrets manager (**HashiCorp Vault KV v2**), and Fleet
fetches the value **on demand** at point of use. Integrate with the secrets manager your
organization already runs instead of keeping a second copy.

- **No local copy.** An external-backed credential stores only `provider` + `reference` (e.g.
  `secret/db/prod#password`); the local sealed blob is empty. Every reader — reveal, SSH/RDP
  credential injection, the database broker, the Kubernetes broker — resolves the value live through
  one new central resolver (`internal/credresolve`), so it always reflects the manager's current
  contents and is never cached.
- **Manager is source of record.** Fleet does not rotate or re-seal external-backed credentials
  (rotate them in the manager); local rotation is refused.
- Locally-sealed credentials are byte-for-byte unchanged. Configure with `FLEET_EXTSECRET_VAULT_*`;
  tick "Store in an external secrets manager" when creating a credential. Migration `0058`. Verified
  end-to-end against a live Vault KV. See docs/external-secrets.md.

Also exposes the `FLEET_KMS_*` and `FLEET_EXTSECRET_*` settings in the reference compose file so the
external-KMS and external-secrets features are configurable in the standard deployment.

## v0.46.0 — Behavior analytics (UEBA)

Surface access patterns that deviate from a user's established baseline, computed from Fleet's own
session records — no ML, no external dependency, just explainable statistics over data you already
have. Four detectors:

- **Off-hours access** — a session started at an hour outside the user's usual pattern.
- **First access to a host** — a user connecting to a host they've never used.
- **New source IP** — a connection from an address not seen before for that user.
- **Activity spike** — session volume well above the user's daily baseline.

A new **Behavior** page (permission `Audit.View`) lists the anomalies with severity; signals are
advisory ("verify before acting"). New `internal/ueba` (pure, unit-tested engine) and `GET
/ueba/anomalies` computed on demand over a 30-day baseline / 24-hour recent window. No migration —
it reads existing session records. Verified end-to-end (off-hours + new-IP anomalies surfaced from
seeded sessions; normal activity produced none).

## v0.45.0 — Kubernetes access brokering

Broker access to Kubernetes clusters the way Fleet brokers SSH/RDP/databases. Register a
cluster (API server + a vaulted bearer-token credential), and Fleet becomes an **authenticating
proxy**: a user — or their `kubectl` — authenticates to Fleet, and Fleet forwards to the cluster's
API server with the vaulted token injected, **auditing every call**. The operator never sees the token.

- **Resource browser** built in: list pods, deployments, services, namespaces, and nodes per
  cluster/namespace with no kubectl required.
- **Raw authenticating proxy** at `/k8s/clusters/{id}/proxy/*` — point `kubectl` at Fleet with a
  Fleet token and reach the cluster through the broker.
- Per-cluster TLS: verify the API server against a stored CA bundle, or skip verification for test
  clusters. New permissions `Kubernetes.Manage` / `Kubernetes.Access`; migration `0057`; new
  **Kubernetes** page. Every call audited (`k8s.proxy`, `k8s.list`).
- Verified end-to-end against a live k3s cluster (listed real pods; proxied the version endpoint).

## v0.44.0 — Policy-as-code: attribute-based access control (ABAC)

Layer contextual **deny** rules on top of RBAC. An access policy can block a host connection
that a user's roles would otherwise permit, based on **host attributes** (environment, tags,
protocol), **time of day** (business-hours windows, including windows that wrap past midnight,
and specific days of week), with **role exemptions**. Policies only ever *restrict* access —
they never grant it beyond RBAC — and **super administrators are always exempt** (no self-lockout).

- Enforced at every interactive connect choke point — **browser SSH terminal, RDP, SFTP**, and the
  **ad-hoc command runner** — immediately after the RBAC/host-access check. Denials return the
  policy's message and are recorded as `access.denied` audit events (rule, host, surface, reason).
- Rules evaluate first-match-by-priority in the configured display timezone. Example: "deny
  production SSH outside 09:00–18:00, except for the SRE role."
- New **Access Policies** page (permission `AccessPolicy.Manage`) and `access-policies` API;
  migration `0056`. The evaluation engine is pure and exhaustively unit-tested; enforcement was
  verified end-to-end (a non-admin blocked from a production host with the rule's message; the
  admin exempt; disabling the rule restores access).
- Note: scheduled/automation runs (Ansible playbooks, PowerShell scripts, scheduled scans) are
  service-account governed and not subject to time-of-day ABAC.

## v0.43.0 — KMS backends: Azure Key Vault & GCP Cloud KMS

Two more external KMS backends for master-key protection (v0.40.0), so the CA and vault
passphrases can be wrapped by the KMS your organization already runs:

- **Azure Key Vault** (`FLEET_KMS_PROVIDER=azure-keyvault`) — wrapKey/unwrapKey (RSA-OAEP-256);
  the key never leaves the vault. Azure AD client-credentials auth with token caching.
- **GCP Cloud KMS** (`FLEET_KMS_PROVIDER=gcp-kms`) — encrypt/decrypt on a cryptoKey. Service-account
  auth via an RS256-signed JWT exchanged for an access token.

Both are implemented against the vendor REST APIs directly — **no cloud SDK** — joining the existing
HashiCorp Vault Transit and AWS KMS backends behind the same `internal/kms` interface, `fleetctl kms`
tooling, and the Settings "Encryption at rest" status card. See docs/kms.md.

## v0.42.0 — Customizable dashboard Quick Connect

The dashboard **Quick Connect** list is now personalizable. Click the tune icon to pick
exactly which hosts appear — and in what order — instead of the automatic top-6. Leave the
selection empty to restore the automatic list (online hosts first). The choice is stored
**per user** and follows your account across browsers and devices.

- New reusable per-user preference store: `user_preferences` table (migration `0055`), store
  helpers, and a self-scoped `GET/PUT /preferences/{key}` API (any signed-in user manages only
  their own preferences; keys are whitelisted). A foundation for further personalization.
- The dashboard falls back gracefully: pinned hosts you can no longer reach are skipped, with a
  hint to update the list.

## v0.41.1 — Offline .guac player: drop a recording anywhere

The offline RDP recording player only accepted a file dropped precisely on a small box.
Now the **entire page** is a drop target: dragging a `.guac` file over the window shows a
large, unmistakable overlay ("Drop your .guac recording to play it — release anywhere on the
page"), and releasing anywhere loads it. The click-to-browse area is also enlarged with
clearer copy. Prevents the browser from navigating away when a file is dropped off-target.

## v0.41.0 — Database broker: MySQL, MariaDB & SQL Server

The database broker (v0.39.0) now speaks three more engines. Register a **MySQL**,
**MariaDB**, or **SQL Server** target alongside PostgreSQL and run brokered SQL through the
jump host with the same vaulted-credential injection, row/statement caps, and `db.query`
auditing — the operator never sees the password.

- Each engine connects over the existing single SSH-tunneled connection: the per-engine driver
  (pgx for Postgres, the MySQL wire protocol for MySQL/MariaDB, TDS for SQL Server) runs over the
  tunnel via a one-shot dialer. No cloud SDK is pulled into the binary.
- The SQL console adapts per engine: engine-aware default port (5432 / 3306 / 1433) and starter
  query (`LIMIT` vs `TOP`). Row-returning statements render a grid; other statements report rows
  affected.
- Migration `0054_database_broker_engines` widens the engine constraint; existing PostgreSQL
  targets are untouched.

## v0.40.0 — External KMS / HSM for master-key protection

Fleet's at-rest secrets (the CA signing key and every credential-vault entry) were already
AES-256-GCM sealed with a passphrase. That passphrase can now be **protected by an external
Key Management Service or HSM** instead of living in the environment as plaintext — the
near-universal enterprise security-review requirement, *"is the master key in a KMS/HSM?"*

- **Unseal-via-KMS.** Wrap your `FLEET_CA_PASSPHRASE` / `FLEET_VAULT_PASSPHRASE` once with the
  external KMS (`fleetctl kms wrap`) and store only the opaque wrapped blob
  (`FLEET_CA_PASSPHRASE_WRAPPED` / `FLEET_VAULT_PASSPHRASE_WRAPPED`). At boot Fleet makes a single
  Unwrap call to recover the passphrase into memory. A stolen disk or database backup is useless
  without live access to the KMS.
- **No re-seal, no format change.** The on-disk sealed-data format is unchanged, so enabling (or
  disabling) a KMS backend needs no migration and no re-encryption — only the passphrase *source*
  moves. The default provider is `local`, which preserves prior behavior exactly.
- **Backends:** **HashiCorp Vault Transit** (encryption-as-a-service; the key never leaves Vault)
  and **AWS KMS** (Encrypt/Decrypt), both implemented against the provider HTTP APIs with **no
  cloud SDK dependency** (SigV4 signing is validated against AWS's published test vector). An AWS
  endpoint override supports KMS-compatible emulators. Azure Key Vault / GCP KMS slot into the
  same `internal/kms` interface next.
- **Tooling & visibility:** `fleetctl kms status | wrap | unwrap`, and a read-only **Encryption at
  rest** card (Settings → Infrastructure) showing the provider, key ID, live backend health, and
  whether each passphrase is KMS-wrapped. New `GET /kms/status` (System.Configure).
- Fail-closed: production refuses `FLEET_KMS_VAULT_SKIP_VERIFY`, and the CA/vault passphrase
  distinctness and length invariants are re-checked after unwrapping. See docs/kms.md.

## v0.39.0 — Database access brokering (PostgreSQL)

Fleet now brokers privileged access to **databases**, not just SSH/RDP hosts. Register a
PostgreSQL target (address, port, database, and a vaulted credential), then run SQL from the
new **Databases** page: Fleet reaches the database **through the jump host**, injects the
vaulted credential (you never see the password), executes your statement, and **audits it**.

- Zero-knowledge: the database password is decrypted in RAM at point of use and never returned
  to the client; the connection authenticates as the credential's user.
- Reuses the existing spine — the jump-host tunnel (`DialRawViaJump` with your session
  certificate), the credential vault, RBAC, and the hash-chained audit log. Every query is
  recorded (`db.query`) with who ran what against which database.
- New permissions `Database.Manage` (register/edit/delete targets) and `Database.Connect`
  (open a session and run queries); a results grid with row/statement caps. Migration
  `0053_database_broker`.
- First engine is PostgreSQL (reuses the bundled pgx driver); the model is built to extend to
  MySQL/others. This version executes one statement per request (no persistent transaction/
  session yet).

## v0.38.0 — Scheduled automatic credential rotation

The credential vault could already rotate a password on its host **on demand**; it can now do
so **automatically on a schedule**. Set a rotation interval (1/7/30/60/90 days) on a password
credential from the Credentials page, and a background job rotates it on its host every
interval — generating a new value, changing it over SSH, verifying it by re-login, and storing
the new sealed version. No one ever sees the password.

- Reaches the host with a short-lived **system certificate** through the jump hop (no user
  session required); the change-and-verify contract is shared with the on-demand path.
- **Backs off on failure** (retries at the next scheduled time rather than every check) and
  emits `credential.rotated` / `credential.rotate_failed` notifications; every rotation is
  audited.
- Leader-gated and RLS-bypassed so one instance rotates due credentials across all tenants,
  with each stored version tagged to the credential's own tenant.
- New knob `FLEET_VAULT_ROTATION_CHECK` (default 30m) sets how often the leader scans for due
  credentials. Migration `0052_vault_rotation`.

## v0.37.1 — Multi-tenancy: keep the audit hash-chain global (append fix)

Completes the audit-chain hardening started in v0.37.0. `AppendAudit` read the previous hash
inside the request's tenant-scoped transaction, so under multi-tenancy an event written while
acting inside a customer tenant chained to that tenant's last *visible* hash instead of the true
global head — corrupting the single global hash chain and defeating tamper-evidence.

The chain-head read, advisory lock, and insert now run under RLS bypass so `prev_hash` is always
the true global head regardless of the caller's tenant, while the row's `tenant_id` is set
explicitly (so tenant-scoped audit reads still work; `tenant_id` is deliberately not part of the
hashed record). Verified: an audit event created while acting inside a customer tenant now chains
to the global head and is tagged with that tenant, and the chain tail is internally consistent.
Single-tenant deployments are unaffected. (v0.37.0 already fixed the verification side to read the
chain globally.)

## v0.37.0 — Compliance evidence pack (PDF)

Adds a single, auditor-ready PDF to the Reports page that complements the existing per-domain
CSV exports. For a chosen date range it bundles:

- an **audit-log integrity attestation** — a genesis-to-latest verification of the hash-chained
  audit log, stated as PASS (chain cryptographically intact) or FAIL with the broken sequence.
  This is Fleet's tamper-evidence guarantee rendered as evidence auditors can file;
- summary statistics for privileged access (sessions, distinct users/hosts), certificate
  issuance (and revocations), scan posture (pass/fail), vulnerabilities (with critical/high
  counts), and privileged-command activity (flagged/blocked).

Generated server-side as a real PDF (pure-Go, CGO-free), white-label aware, with the full
line-item detail still available as the individual CSV exports. Gated by `Audit.View`.

Also fixed: the audit-chain verification (`/audit/verify` and the new attestation) now runs
globally regardless of the caller's tenant — the hash chain is a single cross-tenant sequence,
so a tenant-scoped read would hide rows and falsely report the chain broken.

## v0.36.5 — Multi-tenancy: scope token-authenticated endpoints

Fixes a multi-tenancy correctness bug (single-tenant deployments unaffected). Endpoints that
authenticate with a token instead of the `RequireAuth` middleware — the WebSocket terminal,
session-watch, RDP session, plus the RDP-recording / scan-report streams and the enrollment
agent — resolve the caller under RLS-bypass but then ran their queries without re-applying the
caller's tenant. Under multi-tenancy that made row-level security deny the row: opening a
terminal to one of your own hosts returned "host not found", and the terminal's detached
finalize writes (session-end audit, recording metadata) were silently dropped.

Each such endpoint now scopes its work to the caller's tenant (`Auth.TenantScope`), including
the **detached `context.Background()` contexts** that outlive the request (terminal finalize +
command-policy audit/waiver/approval; RDP disconnect finalize). Verified end-to-end with
multi-tenancy on: the terminal connects and its `session.start`/`session.end` audit events are
recorded under the correct tenant; cross-tenant isolation is unchanged. The live-events socket
needs no change (it pushes in-memory events and issues no tenant-scoped query).

A verification pass over an earlier code review confirmed most flagged issues were already
fixed; this closes the few real remainders.

- **Retention now covers issued certificates and resolved access requests.** The activity-
  retention loop additionally prunes expired `ssh_certificates` (keyed on expiry, so an
  unexpired cert is never removed; the KRL is built from `cert_revocations`, unaffected) and
  resolved `approval_requests` — skipping any pending request or any request still holding a
  live grant, so pruning can never strip a user's access. Both were previously unbounded.
- **WebSocket access tokens no longer travel in the URL.** The browser terminal, live-events,
  and session-watch sockets now carry the short-lived token in the `Sec-WebSocket-Protocol`
  subprotocol instead of a `?token=` query parameter, so it no longer appears in reverse-proxy
  access logs. The server still accepts the query parameter as a fallback for older/non-browser
  clients.
- **Removed dead CSRF-validation middleware.** State-changing API calls authenticate with a
  Bearer token (which a cross-site page cannot forge) and the only cookie-authenticated
  endpoints use SameSite=Strict cookies, so the unused double-submit validator was removed and
  the design documented in place.

## v0.36.3 — Wider third-party CVE coverage on Windows

- Expanded the curated Windows app→CPE dictionary from 19 to 35 entries, so more installed
  third-party software is matched against NVD CVEs during a vulnerability scan: WinRAR,
  TeamViewer, Slack, Oracle VirtualBox, VMware Workstation, GIMP, Audacity, KeePass,
  KeePassXC, Dropbox, Opera, Apache Tomcat, Apache HTTP Server, MySQL Server, nginx, Grafana,
  and Jenkins. Same precision-first rule — only confident NVD vendor/product identifiers;
  apps still not in the dictionary are reported as not scanned rather than guessed. (Zoom,
  Redis, and MongoDB were deliberately left out: Zoom's CPE is inconsistent, and the Redis/
  MongoDB names collide with their separate GUI tools. "MySQL Server" is matched specifically
  so MySQL Workbench doesn't inherit the server's CVEs.)

## v0.36.2 — System Health page reachable on direct load

- **Fixed** the System Health page showing raw `{"status":"ok"}` JSON on a hard refresh or
  direct link. nginx proxies the exact path `/health` to the backend liveness endpoint (for
  infra/monitoring probes), which shadowed the SPA's `/health` route. Moved the UI page to
  **`/system-health`**; the `/health` liveness endpoint is unchanged. In-app navigation was
  never affected — only a direct load of that URL.

## v0.36.1 — Session-replay full-screen fix + tenant-switch UX + multi-tenancy compose wiring

- **Tenant switching is now obvious from anywhere.** While a provider admin is acting
  inside a customer tenant, the top bar shows the tenant's **name** ("Tenant: Acme") on
  every page, next to a one-click **Exit** button that returns to the provider's own view
  (clears the tenant header, refetches under the restored context, lands on the dashboard).
  Previously the only always-visible affordance was a generic "In customer tenant" chip
  that merely linked to the Tenants console — the actual switch-back was buried there.
- **Fixed** the "Exit full screen" control being invisible when replaying an SSH session
  full-screen. The replay renders inside a right-anchored drawer (a modal whose stacking
  context tops out just below the app bar), so a top-right exit button was painted over by
  the app bar — the button existed but couldn't be seen or clicked. Moved it to the
  bottom-right (always clear of the app bar) and padded the top of the overlay so the
  caption and first line of output are no longer hidden behind the bar. (The RDP replay's
  full-screen control was already correct — it renders at the page root, not in a drawer.)
- **Compose:** `FLEET_MULTI_TENANCY` is now passed through to the backend and
  `FLEET_DATABASE_URL` is overridable, so MSP mode can be enabled without editing the
  compose file. Note (documented inline): with multi-tenancy on, the app's DB role must be
  **non-superuser** and lack `BYPASSRLS`, or row-level isolation is silently ineffective.

## v0.36.0 — FIPS 140-3 mode (opt-in, default off)

The FIPS 140-3 mode is available. Opt in with
`FLEET_FIPS_MODE=true` (default off — non-FIPS deployments are unchanged: Ed25519,
WireGuard, Argon2id as before).

- **FIPS 140-3 crypto profile** via Go 1.24's native module (`GODEBUG=fips140=on`,
  runtime toggle, one image): ECDSA P-256 CA + identities, pinned SSH suites
  (AES-GCM/ECDH-P256/HMAC-SHA256), PBKDF2 at-rest KDF + password hashing, SHA-256 TOTP,
  ES256/RS256 WebAuthn, TLS 1.2 floor on outbound clients. Fails closed if the module
  isn't active in FIPS mode.
- **Certificate-authenticated overlay (OpenVPN)** as a FIPS alternative to WireGuard,
  **selectable per host** at enrollment (WireGuard remains the default). Its own X.509
  overlay PKI. (A strongSwan/IPsec variant was prototyped but removed until it can be
  validated on real IPsec-capable hosts.)
- **Migration toolset** (`fleetctl fips check` / `reseal-secrets` / `flag-stale-passwords`,
  verify-then-upgrade-on-login) + a FIPS readiness card in System Health.

Validated in Docker: a FIPS deploy boots with the module active, ECDSA CA, and a green
readiness verdict; a default deploy is byte-for-byte unchanged. Migrations
`0049_overlay_pki`, `0050_host_overlay`.

## v0.35.0 — Multi-tenancy (MSP) — experimental, default off

One deployment can now serve multiple **isolated customer tenants**, for MSPs. Opt in
with `FLEET_MULTI_TENANCY=true` (default off — with it off, Fleet is unchanged).

- **Provider manages many customers.** Existing data lands in a seeded **Provider**
  tenant; its admins get a **Tenants** console to create customer tenants and **switch
  into** one to operate within it. Each customer's hosts, users, sessions, credentials,
  audit and everything else are fully isolated.
- **Enforced by Postgres row-level security**, not hand-scoped queries: a `tenant_id` +
  RLS policy on every tenant-scoped table, driven by the request's tenant — so a missed
  filter physically cannot leak, and an unscoped request sees nothing (fail closed).
  Proven end-to-end (a provider can't see a customer's hosts, and vice versa).
- **Requirement:** enabling it needs the app's database role to be a **non-superuser**
  (Postgres superusers ignore RLS). See docs/multi-tenancy-plan.md.

Treat as **experimental** until you've validated it for your data; single-tenant
deployments are entirely unaffected. Migration `0051_tenancy`.

## v0.34.0 — Offline .guac player + content-search keyword highlighting

- **Offline RDP recording player.** A self-contained, cross-platform HTML player for
  downloaded `.guac` recordings — get it from **RDP recordings → "Offline player"**. It's
  a single file that runs in any browser on any OS with **no server and no install**: open
  it, drop in a `.guac` file, and play/pause/seek/full-screen. Recordings are read locally
  and never uploaded. (Bundles Apache Guacamole's player, Apache-2.0.)
- **Content search highlights the keyword.** In Sessions → Content search, the searched
  term is now highlighted in each result snippet for easier scanning.

## v0.33.7 — Full-screen for RDP replay + a visible SSH exit button

- **RDP session replay can now go full screen** — a control it never had. The Guacamole
  desktop scales to fill the viewport, with the same Esc-to-exit and a floating "Exit
  full screen" button.
- **SSH replay exit is now unmissable** — replaced the small top-row icon with a floating
  **"Exit full screen (Esc)"** button fixed to the viewport corner, above the player.

## v0.33.6 — Session replay: reliable full-screen exit

Fixes the recorded-session full-screen view: **Esc now always exits** (the key listener
moved to the capture phase, so the terminal — which could swallow keydowns when focused —
no longer eats it), and the exit control is now a clear **"Exit full screen (Esc)"
button** instead of a small corner icon.

## v0.33.5 — Ask AI: deterministic fast-path for obvious questions

Small local models often mis-route clear questions (answering "who ran df" with fleet
health, or dumping the whole host for an updates question). Ask AI now **bypasses the
model's tool choice** for a couple of unambiguous shapes: it detects the intent, runs
the correct tool directly with the right arguments, and has the model only narrate the
result (with tools disabled so it can't mis-route):

- **"who ran / typed / executed `<command>`"** (optionally "on `<host>`") → `search_commands`.
- **"what are the pending updates" / "which packages need updating" / "what security
  updates are pending"** (optionally per host) → `host_updates`.

It's high-precision — anything it doesn't clearly recognize still goes through the normal
model-driven tool loop, so nothing else changes. This makes those answers reliable
regardless of how capable the configured local model is.

## v0.33.4 — Ask AI: focused host_updates tool (no more whole-host dump)

Asking Ask AI "what are the pending updates?" used to answer via `host_detail`, which
returns the entire host — so the UI rendered the full host card (OS, filesystems,
interfaces) beneath the answer. A new **`host_updates`** tool returns just the pending
packages (host · package · target version · security) as a focused table, for one host
or all accessible hosts. Update questions now route there; `host_detail` is reserved for
filesystem/network deep-dives. Scoped to the caller's accessible hosts.

## v0.33.3 — Ask AI: route "who ran <command>" to the command tools

Tightened the assistant's tool-selection guidance so questions like "who ran df" /
"did anyone run rm -rf" go firmly to **search_commands** (interactive terminals) and
**recent_commands** (Fleet Run-Command), instead of being answered by the fleet-health
tool. `fleet_insights` is now scoped explicitly to health/capacity questions only.
Helps smaller local models route these correctly. (Prompt-only; requires the assistant
tools from v0.33.0 to be deployed — if your Sessions page has no "Commands" tab, deploy
the newer build first.)

## v0.33.2 — Sessions: "Commands" search view

A new **Commands** tab on the Sessions page searches the commands users **typed** in
recorded terminal sessions ("who ran `X`"), backed by the v0.33.0 command index — fast
and across all history (unlike the on-the-fly Content search). Filter by host, see
user/host/time/command, and jump straight to the session replay. Gated by
Session.Replay, scoped to the caller's accessible hosts, and audited. Results are a
best-effort reconstruction (tab-completion / recalled history may be partial) and cover
recorded sessions only. New endpoint `GET /api/v1/session-commands`.

## v0.33.1 — Host detail: pending-update package list

The host-detail dialog now shows the **pending update packages** collected in v0.33.0,
not just the count: a scrollable "Pending updates" list under System, each entry showing
the package name and target version, security fixes flagged and sorted first. Appears
once the monitor has collected the list (frontend-only; no migration).

## v0.33.0 — Ask AI: command history & update details; session-replay full screen

Four enhancements, led by deepening the Ask AI assistant.

- **Ask AI — "who ran command X".** Two new assistant tools:
  - **`recent_commands`** — the authoritative record of commands run through Fleet's
    Run-Command feature (exact command, who ran it, target, status, exit code, when),
    gated by Command.Run.
  - **`search_commands`** — searches the commands users **typed** in recorded interactive
    SSH sessions, reconstructed from the recordings (backspace/Ctrl-U/escape aware). A
    background indexer builds a full-text index (backfilling existing recordings); search
    is scoped to the caller's accessible hosts and gated by Session.Replay. This is a
    best-effort reconstruction (tab-completion / history-recall may be partial), so the
    assistant qualifies results as "typed", and it only covers recorded sessions.
- **Ask AI — which packages need updating.** The monitor now collects the actual pending
  **update package list** per host (name, target version, security flag — apt/dnf/yum),
  not just the counts, so `host_detail` (and the API) can answer "which packages need
  updating on web-01".
- **Session replay — full screen.** The recorded-session player has a full-screen toggle
  (Esc to exit) with a larger font, re-fitting on resize, so recordings are easier to read.

Migrations: `0049_host_update_packages`, `0050_session_commands`. Command indexing runs
in the background after startup; on a large recording archive the first pass may take a
few minutes to backfill.

## v0.32.3 — Fix: vulnerability scan 504 "scan timed out" on large hosts

The grype scanner sidecar capped each scan at **5 minutes** (`GRYPE_SCAN_TIMEOUT`,
its built-in default) while the backend was willing to wait **20 minutes**
(`FLEET_VULN_SCAN_TIMEOUT`) — and the bundled compose never overrode the scanner's
cap. A host with a large package database (e.g. an ML/CUDA box with thousands of
installed packages) legitimately takes longer than 5 minutes to scan, so it always
came back as `scanner error (504): scan timed out` even though the backend would have
waited.

- The scanner's per-scan timeout now **defaults to 20 minutes**, matching the backend,
  and is exposed as `GRYPE_SCAN_TIMEOUT` (seconds) in the compose file and
  `.env.example`. Raise both it and `FLEET_VULN_SCAN_TIMEOUT` further if a host still
  times out.
- **Deploy:** pull, then recreate the scanner: `docker compose up -d grype-scanner`
  (no rebuild needed unless you also want the updated in-image default). Existing
  `.env` values are respected.

## v0.32.2 — Fix: blank Disaster Recovery page + stuck Authentication settings

Two UI robustness fixes.

- **Disaster Recovery page no longer blanks on a single instance.** The page crashed
  to a white screen when this instance is a primary with no downstream standbys —
  the API returned `replicas: null` and the page called `.length`/`.map` on it. The
  page now normalizes that to an empty list, and the backend returns `[]` instead of
  `null`.
- **Authentication settings (OIDC / LDAP / SAML) no longer hang on "Loading…".** If a
  card's config request fails, it now shows a clear error with a **Retry** button and
  a hint to hard-refresh (a stale cached bundle after an update is the usual cause),
  instead of an indefinite spinner. The backend endpoints were already fine; this is
  purely making the cards fail visibly rather than silently.

**Deploy:** `make redeploy-single`, then **hard-refresh your browser**
(Ctrl/Cmd-Shift-R) — a redeploy invalidates the old bundle/session, and a cached SPA
can otherwise show stale-load symptoms.

---

## v0.32.1 — Fix: fleet-wide vulnerability scans timing out at the scanner

A scheduled "scan all hosts" could fail several hosts with
`scanner unreachable: Post "http://grype-scanner:8000/scan": context deadline
exceeded (Client.Timeout exceeded while awaiting headers)`. Root cause: the
scheduler fans out up to 16 host scans at once, but the grype-scanner sidecar ran a
**blocking** `grype` call inside an **async** handler on a **single worker** — which
froze its event loop and processed scans strictly one at a time. Hosts stuck at the
back of that serialized queue blew past the backend's timeout.

- **Scanner now processes scans concurrently, bounded.** grype runs off the event
  loop with a small concurrency cap (`GRYPE_SCAN_CONCURRENCY`, default 2 — grype is
  CPU/memory-heavy, so it's deliberately modest and tunable per host size). Extra
  requests queue with the worker responsive instead of freezing it.
- **Backend scan timeout is now realistic + configurable.** A per-host request that
  legitimately waits behind others no longer fails at a hard 6 minutes; the bound is
  `FLEET_VULN_SCAN_TIMEOUT` (default **20 minutes**), applied to both the HTTP client
  and the per-scan context.

**Deploy:** rebuild the scanner + backend — `make redeploy-single` (it rebuilds
`grype-scanner` and `backend`). Then re-run the scan or clear the recent failures on
the Vulnerabilities page. On a small box, keep `GRYPE_SCAN_CONCURRENCY` at 1–2; raise
it on a beefier host.

---

## v0.32.0 — Read-only DR standby mode (usable warm standby)

Makes the two-site warm standby (v0.31.0) actually **runnable on the replica**.
Previously, a standby Fleet pointed at a read-only replica couldn't serve requests
(login/audit/heartbeat all write), so the DR console could only *finish* a failover
after the database was promoted by other means. Now Fleet detects the replica and
runs in a dedicated **standby mode**:

- **Automatic detection.** On startup Fleet checks `pg_is_in_recovery()`. If its
  database is a replica it boots read-only: **migrations are skipped**, **no
  background writers start** (cluster/monitor/scheduler/CA — none of which a replica
  can service), and the API surface is reduced to a health check plus the DR
  standby console. Migrations auto-skip on a replica, so the old
  `FLEET_MIGRATE_ON_START=false` requirement is now just belt-and-suspenders.
- **Break-glass standby console.** The web UI detects standby posture (unauthenticated
  `GET /dr/mode`) and replaces the whole app with a console showing **live replication
  lag** and a **Promote this instance to primary** action — authenticated by a static
  **`FLEET_DR_STANDBY_TOKEN`** (a login can't be used: the replica can't write a
  session). Promotion runs `pg_promote()` and the instance **restarts into full normal
  mode** against the now-primary database (give the container a restart policy).
- **Peer health still works:** a standby answers `/ready`, so the primary's DR page
  shows it reachable.

Validated end-to-end against a real streaming replica (base-backup standby):
detection, migration/writer suppression, lag reporting, token-gated promotion, and
the restart-into-primary handoff. See the updated **Two-site warm standby** section of
`docs/disaster-recovery.md`. No migration; standby mode is inert until an instance is
actually pointed at a replica, so existing single-instance deployments are unaffected.

## v0.31.0 — Disaster Recovery console (two-site warm standby)

A new **Disaster Recovery** page (nav; `DR.Manage` — Super Administrator +
Administrator by default) for running Fleet as **two independent instances** — an
active primary and a warm standby at a second site — with administrator-triggered
**failover / failback** from the UI.

- **Live status:** whether this instance's PostgreSQL is a **standby (in recovery)**
  and its **replay lag**, the **connected standbys** when it's a primary (from
  `pg_stat_replication`), and the **reachability of the peer instance** (`/ready`).
- **Force failover / Force failback:** run from the instance taking over. Each
  optionally runs **`pg_promote()`** on this instance's database (enable "Also
  promote this database" when the standby steps up), then **POSTs a configured
  webhook** — which you wire to your DNS repoint + standby jump-host WireGuard
  bring-up — and audits every step (`dr.failover` / `dr.failback` / `dr.promote`,
  hash-chained). Guarded by a confirmation dialog.
- **Configuration:** role label (standalone / primary / standby), peer URL, and the
  failover/failback webhook URLs.

**Scope boundary (by design):** the console is a **trigger + status surface**, not
the orchestrator — Fleet does not replicate the database or move DNS itself.
`pg_promote()` works only when this DB is actually a standby and the role may run it
(superuser-only unless you `GRANT EXECUTE ON FUNCTION pg_promote`); the console
surfaces the DB's error verbatim otherwise. Full runbook — replication setup, the
mandatory secret-parity checklist (`FLEET_CA_PASSPHRASE` is the linchpin), host
reachability options, and the failover/failback procedures — is in the new **Two-site
warm standby** section of `docs/disaster-recovery.md`. Migration `0048` (the
`DR.Manage` permission) applies automatically; no schema tables are added.

## v0.30.0 — Ad-hoc command runner (Linux)

Run a one-off shell command on one or many Linux hosts without authoring a
playbook — the lightweight counterpart to Ansible playbooks and PowerShell scripts.
A new **Ad-hoc Command** tab on the **Automation** page (`Command.Run`) takes a
command and a host/group target, runs it over the jump host, and streams the
aggregated per-host output; recent runs are listed with status.

- **Governed by command control.** Every command is evaluated against the
  command-control policy (v0.29.0) per host *before* it runs: a **blocked** command
  is refused on that host, an **approval-gated** one is refused and files an
  approval request (and runs once a waiver is granted), and a **flagged** one runs
  with an audit + alert. So the ad-hoc runner can't be used to bypass the rules
  that apply to interactive sessions.
- **Safe + scalable by construction.** Runs as each host's configured SSH user
  through the jump host, with a **bounded worker pool** (6 hosts at once), a
  per-host **timeout**, and a **4 MiB output cap**. Windows hosts are rejected (use
  PowerShell scripts). HA-aware: a run abandoned by a dead instance is reconciled to
  `failed` on startup. Every run is audited (`command.run`).
- API: `POST /commands/run`, `GET /command-runs`, `GET /command-runs/{id}`.
  Migration `0047` (the `command_runs` table + the `Command.Run` permission,
  Administrator-only by default) applies automatically.

This is the raw ad-hoc runner deferred from v0.25.0 — it ships now that command
control exists to govern it, rather than ungoverned.

## v0.29.0 — Command control (privileged-command policy)

Define rules that match commands typed in interactive terminal sessions and act on
them — a core PAM control. A new **Command Control** page (`CommandPolicy.Manage`)
manages the ruleset; enforcement happens at the terminal relay.

- **Three per-rule actions:** **flag** (allow, but audit + alert), **block**
  (refuse to run — the relay withholds the command and clears the line), and
  **approval** (refuse until an approver grants a time-boxed waiver, then the user
  re-runs it). Patterns are RE2 regular expressions matched against each command
  line.
- **Scope:** each rule is **global** or scoped to a **host group** (e.g. stricter
  blocks on production). A host's applicable rules are loaded once per session.
- **Approvals:** an approval-gated command creates a request; an admin approves it
  from the Command Control page (you can't approve your own — separation of duties),
  granting a 10-minute waiver. Every decision is audited and notified.
- **Fully audited:** `command.flagged` / `command.blocked` /
  `command.approval_requested` / `command.approved_run`, plus notification event
  types you can route (flagged / blocked / awaiting-approval).

**Important — what this is and isn't:** enforcement inspects the interactive input
stream, so it is a strong **deterrent and a complete audit trail**, not a
cryptographic guarantee. A determined insider can obfuscate (paste-splitting,
base64, launching a sub-shell or editor). It raises the bar and records intent; it
does not make a hostile operator harmless. Hosts with **no** rules are completely
unaffected — the input path is an unchanged, zero-overhead passthrough. Migration
`0046` (rules + approvals + the `CommandPolicy.Manage` permission) applies
automatically.

## v0.28.0 — Fleet-wide session content search

Search across recorded terminal sessions for a string — "who ran `X`, where, and
when" — instead of opening recordings one by one. A new **Content search** tab on
**Session Replay** (`Session.Replay`) takes a query and returns the matching
sessions with **context snippets**, each linking straight to its replay.

- Searches the recorded session content (the terminal output stream, which echoes
  what was typed), across the most recent recordings. ANSI escape codes and control
  characters are stripped so matches are on the visible text, not terminal codes.
- **Bounded by design:** a single query scans the most recent 500 recordings, caps
  the bytes read per recording, and returns snippets/results within fixed limits —
  the response says how many recordings were scanned and whether the set was capped
  (so you can narrow with a more specific term). Keeps search cost predictable
  regardless of history size.
- Session content is sensitive, so **every search is audited** (`session.search`,
  with the query and match count). Endpoint: `GET /sessions/search?q=`.

*Note:* this searches recorded **content**; there is no separate parsed
command-history store (Fleet records full PTY sessions, not individual commands).

## v0.27.0 — In-browser config-file editor

Edit a remote text file — `/etc/nginx/nginx.conf`, a `.env`, a unit file — right in
the **Files** browser, without downloading, editing locally, and re-uploading. Each
file row now has an **Edit** (pencil) action that opens the contents in a monospace
editor; **Save** writes it back over the same audited jump-host/SFTP path.

- **Automatic on-host backup.** Before overwriting, Fleet copies the current file
  to `<name>.fleetbak-<timestamp>` on the host (toggle off if you don't want it), so
  a bad edit is always recoverable. The save reports where the backup went.
- **Safe by construction.** The editor refuses files over 2 MiB or that look
  binary (contain NUL), and **preserves the file's existing permissions** on save.
  It's gated by the same **`File.Transfer`** permission and per-host access as
  upload — this is a nicer, audited UX over a capability SFTP already had (you can
  overwrite files today), not a new one. Reads and writes are audited
  (`sftp.read` / `sftp.edit`).
- New endpoints: `GET /hosts/{id}/sftp/read`, `POST /hosts/{id}/sftp/write`.

## v0.26.0 — Expiry & Rotation dashboard

A new **Expiry & Rotation** page (nav; `System.Configure`) gives one at-a-glance
view of the credentials and keys that need lifecycle attention, so nothing silently
ages out:

- **API tokens** that are **expired**, **expiring** within 30 days, or **unused**
  (never used and older than 30 days, or not used in 90 days).
- **Vault credentials** not **rotated** in over 90 days (based on the last version
  written — pairs with the `Credential.Rotate` action).
- **User passwords** older than 90 days (active accounts).
- **CA keys** older than a year (rotation hygiene, informational).

The page shows per-status counts and a table ranked most-urgent first. Everything
is **metadata only** — no secret material is ever read or shown. Backed by a single
read-only endpoint, `GET /lifecycle/expiry`; a healthy fleet shows "nothing needs
attention." Thresholds are fixed for now (they may become configurable later).

## v0.25.0 — Bulk host actions

Act on many hosts at once. Select hosts in the grid (the checkboxes were already
there) and a **Bulk actions** menu appears in the toolbar:

- **Run vulnerability scan** on the whole selection (Linux via grype, Windows via
  MSRC + third-party — each host scanned by the right method).
- **Refresh facts** — queue a re-collect of pending updates / inventory on the
  next monitor sweep for every selected host.
- **Maintenance…** — silence alerts on the selection for 1 / 4 / 8 / 24 hours, or
  clear an active window, in one step (pairs with v0.24.3 maintenance windows).
- **Edit tags…** — add and/or remove tags across the selection (comma- or
  newline-separated); useful for driving dynamic-group membership at scale.

Each action reuses the existing per-host operation and its permission
(`Host.Scan` / `Host.View` / `Host.Edit`), and the server filters the selection to
hosts you can actually access — so a bulk action can never reach a host you
couldn't touch one at a time. Bulk operations are bounded (max 1000 hosts/request)
and audited (`host.bulk_*`). New endpoints: `POST /hosts/bulk/refresh`,
`/hosts/bulk/maintenance`, `/hosts/bulk/tags`, and `hostIds` on `POST /vuln-scans`.

*Note:* a **raw ad-hoc command runner** (type a shell command, run it on a
selection) is intentionally **not** here yet — it's the execution surface the
upcoming **privileged-command policy** work will govern, so it ships alongside
those guardrails rather than ungoverned. Today, run vetted automation in bulk via
the Automation page (playbooks/scripts) or a group schedule.

## v0.24.5 — Fix: couldn't schedule a Vulnerability DB update

The **Create** button stayed greyed out when adding a **Vulnerability DB update**
(`vulndb`) schedule. That kind is fleet-wide and has no host/group target, but the
form still required a target to be selected before enabling **Create** — so it
could never be saved. The button now only requires a target for the kinds that
have one (scan / vulnscan / playbook / script); `vulndb` can be scheduled again.
Frontend-only; the backend already accepted target-less `vulndb` schedules.

## v0.24.4 — Conditional access (IP allowlist + concurrent-session limits)

Gate sign-in on **where** a user connects from and **how many** sessions they may
hold at once — a core PAM control, enforced at session creation across **every**
login method (password, LDAP, OIDC, SAML) so there's no per-IdP bypass.

- **Global policy** under **Settings → Authentication → Conditional access**: an
  **IP allowlist** (CIDRs or bare IPs, one per line — empty = any network) and a
  **max concurrent sessions per user** (0 = unlimited). Saving an allowlist that
  wouldn't include your *own* current IP is **rejected**, so you can't lock the
  fleet out in one click.
- **Per-user overrides** from a user's **Access policy…** action: each dimension
  independently overrides the global default or inherits it (e.g. exempt a service
  admin from the office-network restriction, or give one user a tighter limit).
- **On denial:** the login is refused with a clear message (SSO users land back on
  the login page with the reason), and a `login_blocked` auth event is recorded.
  Idle/absolute session timeouts (already configurable via `FLEET_SESSION_IDLE_TTL`
  / `FLEET_SESSION_ABSOLUTE_TTL`) are unchanged.
- API: global policy via the existing `PUT /settings/session_policy`; per-user via
  `GET/PUT/DELETE /users/{id}/session-policy` (`User.Edit`, audited).

**Client-IP note:** behind a reverse proxy, set `FLEET_TRUSTED_PROXIES` (off by
default) so the allowlist matches the *user's* IP and not the proxy's. Migration
`0045` (per-user override table) applies automatically.

## v0.24.3 — Maintenance windows (silence a host's alerts while you patch)

Mark a host **in maintenance** so its offline / updates-pending / scan-failure
signals stop firing while you patch, reboot, or otherwise take it down on purpose —
no more chasing an "offline" alert you caused yourself.

- **Silence from host details.** The host-details dialog gains a **Silence alerts**
  action (1 / 4 / 8 / 24 hours) and, while active, an **End maintenance** button. A
  host in maintenance shows an **In maintenance** chip in the details header and a
  **maint** chip on the Hosts grid, so a deliberately-silenced host reads differently
  from a genuinely-broken one.
- **What's suppressed.** While the window is open, the monitor doesn't emit
  offline/recovered **alerts** for the host and the **dashboard insights** skip it —
  so it drops out of "needs attention" — but health-checking, fact collection, and
  metrics keep running, so status is still current when you look. The window ends
  automatically when the timer passes.
- API: `POST /hosts/{id}/maintenance` (`{minutes}`, default 60, capped 30 days) and
  `DELETE /hosts/{id}/maintenance`, both gated by `Host.Edit` and audited
  (`host.maintenance_set` / `host.maintenance_clear`).

**Deploy:** migration `0044` (adds `hosts.maintenance_until`) applies automatically.

## v0.24.2 — `make redeploy-single`: update app code without dropping the overlay

Root-caused the recurring "hosts offline for minutes after a deploy" on a single
instance: `make up-single` runs `compose up -d --build`, which **recreates the
jump-host container** — tearing down the WireGuard overlay so every managed host
has to re-handshake before the monitor can reach it (leader election was already
proven instant; this was the actual cause).

New **`make redeploy-single`** updates only the app services
(`backend frontend grype-scanner`) in place, leaving the jump host and overlay
**running** — so a code deploy no longer disrupts host connectivity (just the
few-second backend restart). Use `up-single` for the initial bring-up or jump-host
changes; use `redeploy-single` for routine code updates.

## v0.24.1 — Monitor sweeps promptly on becoming leader (offline-after-restart)

Compounding the leader-handoff delay: while an instance wasn't leader yet, the
monitor's timer still reset to the full sweep **interval** each tick, so even once
it became leader the first host sweep could be up to a whole interval away — hosts
stayed "offline" long after leadership settled. Now the monitor **polls every 5s
until it's leader**, then sweeps and returns to the normal interval — so the first
sweep lands within ~5s of taking over. Combined with v0.23.3's stranded-lock
reclaim, a restart's offline window is now bounded to a few tens of seconds
(instant on a clean handoff).

## v0.24.0 — Scheduled vulnerability scans + CVE database updates

The **Schedules** page gains two new kinds:

- **Vulnerability scan** (`vulnscan`) — run a vuln scan on a recurring schedule
  against a host or group. Works for **Linux** (grype packages) and **Windows**
  (missing Microsoft updates via MSRC + curated third-party apps) in one schedule
  — each host is scanned by the right method. (The engine already supported this;
  it just wasn't creatable — now it is.)
- **Vulnerability DB update** (`vulndb`) — refresh the CVE databases on a schedule:
  the grype vulnerability DB and the MSRC (Windows) mapping, online. Not
  host-targeted (it's fleet-wide); runs in the background so a long DB download
  doesn't block the scheduler.

Set them up under Schedules → "What to run", with the usual interval/daily/weekly
recurrence. Disabled by default like all schedules.

## v0.23.3 — Faster leader takeover after a restart (reclaim stranded lock)

A restart could leave hosts **offline for minutes**: the new backend couldn't
acquire the Postgres leader advisory lock until Postgres reaped the *old* instance's
dropped connection, and the monitor only sweeps as leader. The v0.20.3 graceful
release fixed the clean case, but an unclean stop (SIGKILL, crash, or a pre-fix
outgoing version) still stranded the lock — which is exactly what a single-instance
`make up-single` hit.

Now the **incoming** instance self-heals: if the leader lock is held but no other
instance has a live leader heartbeat, it terminates the stale holder's connection and
takes over — bounding the offline window to the lease (~30s) instead of however long
Postgres takes to notice the dead socket. Also set `stop_grace_period: 30s` on the
backend so the clean, instant handoff has time to complete before SIGKILL.

## v0.23.2 — Host details: "Refresh facts" (don't wait for the hourly check)

Pending-updates counts (and the Windows software inventory) are collected on an
hourly cadence to keep the WinRM/WUA searches cheap, so after patching a host the
dashboard's "security updates pending" can lag until the next check. Host details
now has a **Refresh facts** button that clears the update-check timestamp so the
monitor re-collects that host on its **next sweep** (typically within a minute)
instead of waiting the hour. `POST /hosts/{id}/refresh` (Host.View + access).

## v0.23.1 — Windows third-party app CVE coverage (CPE → grype)

Windows vuln scans now also cover **third-party applications** — Chrome, Firefox,
VLC, 7-Zip, OpenSSL, Node.js, Wireshark, etc. — alongside the Microsoft/MSRC
findings, closing the gap versus the Linux package scan.

- The scan inventories installed software over WinRM (v0.23.0), maps the **curated**
  apps to **CPEs** (`internal/cpe` dictionary, precision-first), builds a CycloneDX
  SBOM, and scans it with the existing **grype** sidecar (new `/scan-sbom` endpoint)
  — matching the CPEs against NVD. Third-party findings merge with the MSRC ones.
- Apps not in the curated dictionary are **not** guessed at (a wrong CPE would
  mislead); coverage ("installed / mapped") is logged. The dictionary starts with
  ~20 high-value apps and is meant to grow.

**Deploy note:** the grype-scanner sidecar gained an endpoint, so rebuild it
(`docker compose build grype-scanner && docker compose up -d grype-scanner`). No
new CVE data source — it reuses grype's existing (online/offline) NVD database.

## v0.23.0 — Windows software inventory (over WinRM)

Fleet now inventories the **installed applications** on Windows hosts, read over
WinRM from the registry Uninstall keys (64- and 32-bit views; Windows/KB updates
filtered out — those are the MSRC path). It's the foundation for third-party CVE
coverage (next), and useful on its own:

- The monitor refreshes each Windows host's software list hourly (same cadence as
  the updates check), stored in a new `windows_software` table (migration `0043`).
- Host details now show an **Installed software (N)** section for Windows hosts.
- API: `GET /hosts/{id}/software`.

Registry reads are fast and side-effect-free (no `Win32_Product`).

## v0.22.1 — Vulnerabilities: fixable subset + severity filtering

Both scanners already report only what's actually on each host (grype reads the
real installed-package DB; the Windows scan uses WUA applicability), but grype's
model surfaces a long tail of low-severity and unfixable ("no fix available")
CVEs. This adds a way to focus on what's **actionable**:

- **Fixable count in the roll-up.** Each host row now shows a **Fixable** column —
  the subset of findings that have an available fix version — next to the total
  (e.g. "380 fixable / 2690 total"). Computed at scan time and stored (migration
  `0042` adds `vuln_scans.fixable`); existing scans show 0 until re-scanned.
- **Filters in the findings view.** A **Fixable only** toggle (findings with a fix
  version) and per-severity toggles, with Negligible/Unknown hidden by default and
  a "showing X of Y" count. This makes the Linux view directly comparable to the
  Windows "missing patches" view — present *and* fixable.

No scanning changes; both filters work on existing scan data.

## v0.22.0 — Windows CVE data from MSRC (real CVE/severity/CVSS)

Windows vulnerability scans now report **real CVE IDs, MSRC severity, and CVSS
scores** — not just "N missing security updates." The Windows Update Agent reports
which KBs a host is missing, but not (reliably) the CVEs/severity they remediate;
that authoritative data lives in Microsoft's **Security Update Guide** (CVRF), keyed
by KB. Fleet now caches that KB→CVE mapping and enriches each finding with it.

- **New `msrc` package** parses CVRF documents; migration `0041` adds
  `msrc_updates` (KB→CVE, severity, CVSS, vector, title, release).
- **Two ways to load the data**, mirroring the grype DB, under **Vulnerabilities →
  Windows CVE data (MSRC)**:
  - **Update online** — fetches the last `FLEET_MSRC_MONTHS` releases (default 12)
    from `api.msrc.microsoft.com` (only when you click it; no automatic egress).
  - **Import offline** — for air-gapped deployments: upload a **zip of CVRF JSON**,
    a JSON array of documents, or a single CVRF JSON document.
- The Windows scan looks up each missing KB in the mapping and emits **one finding
  per remediated CVE** with real severity/CVSS (linked to its MSRC page). When a KB
  isn't in the mapping yet, it falls back to the prior KB-level finding, so scans
  still work before the data is loaded.

## v0.21.3 — Clear recent scan failures from the Vulnerabilities page

The "Recent failures" banner now has a **Clear** button that removes failed scan
records (error-only rows with no findings) — `DELETE /vuln-scans/failed`, gated by
`Host.Scan`. Useful for dismissing stale failures, e.g. a Windows host that failed
via the old SSH path before Windows scanning existed (v0.21.0).

## v0.21.2 — Prove a session rode the WireGuard overlay (audit + indicator)

Two ways to confirm/prove a connection went over WireGuard, rather than inferring
it from latency:

- **Audit provenance (proof).** Session-start audit events now record the exact
  address the session was brokered to and whether it is the host's overlay
  address: `session.start` (SSH) and `session.rdp_start` (RDP) carry
  `targetAddress` and `overlay: true|false`. Because the audit log is hash-chained
  and tamper-evident, this is defensible evidence — combined with the (also
  audited) strict-overlay policy being enabled — that a given session used the
  WireGuard overlay. Filter the Audit page by the session action to produce it.
- **At-a-glance indicator.** A green **WireGuard** chip now appears on the Hosts
  and Terminals pages for any host reachable over a healthy overlay (the
  affirmative counterpart to the existing "WG down" chip), so a healthy overlay is
  visible instead of showing nothing. Note: the per-host **latency** figures are
  not comparable across protocols — SSH latency is a full handshake, RDP latency
  is a bare TCP connect — so a lower RDP number is expected and says nothing about
  whether WireGuard is in use.

## v0.21.1 — Clarify: strict overlay mode covers Windows RDP

The **Strict overlay — require WireGuard** setting already forces enrolled hosts
with a WireGuard address to be reachable *only* over the overlay for **RDP**
(Windows desktop) sessions, not just SSH terminal and file transfer — the RDP
connection path has honored it since v0.19.2. The setting's help text only
mentioned terminal and file transfer, so this updates the copy to state that RDP
is covered too. No behavior change: turning it on means a Windows host whose
tunnel is down has its RDP session refused rather than quietly falling back to the
host's direct address.

## v0.21.0 — Vulnerability scanning for Windows hosts

Vulnerability scans now work on Windows (RDP) hosts, alongside the existing
Linux/Grype scans — same **Vulnerabilities** page, same findings/severity model,
same scheduling.

On Windows a host's vulnerabilities are the CVEs remediated by its **missing
security updates**, sourced directly from Microsoft's update metadata via the
Windows Update Agent over WinRM (offline search — no external CVE database, no
grype, no network round-trip). Each missing security update becomes one finding
per CVE it fixes, with severity mapped from **MSRC severity**
(Critical→Critical, Important→High, Moderate→Medium, Low→Low); the CVE links to
its MSRC page and the "fix" is the KB to install. CVSS shows "—" (Microsoft's
metadata is severity-based, not CVSS).

- `internal/vulnscan.Run` branches on `host.Protocol == "rdp"` to the WinRM path;
  Linux hosts are unchanged. Authenticated with the host's open-policy vault
  credential (scans are unattended), tunneled through the jump host.
- Previously, scanning a Windows host silently failed (no SSH / no package DB);
  now it produces real findings. Works for manual scans and group schedules.

## v0.20.4 — Configurable PowerShell script timeout (Settings)

The per-host PowerShell script timeout is now operator-configurable under
**Settings → Hosts → PowerShell scripts** (was fixed at 15 minutes). Set how long
a script may run on a single Windows host before it's stopped (1–240 minutes,
default 15); the whole-run timeout scales from it and the concurrency-bounded
batch count. Stored on the `scripts` setting object as `{"timeoutMinutes": N}`.

For very long jobs (e.g. installing large Windows updates, which the WinRM session
can't hold open — and which the Windows Update Agent won't install from a remote
session anyway), the right pattern is a fire-and-forget script that starts a local
scheduled task on the host and returns, rather than raising this timeout.

## v0.20.3 — Fix: release cluster leadership before the DB pool closes on shutdown

A backend restart/deploy could leave the fleet showing all hosts **offline** for
minutes (and interrupt in-flight singleton work) until leadership was re-acquired.
The cluster coordinator releases its Postgres leader advisory lock on shutdown, but
that step-down ran asynchronously in its goroutine while `main` independently
drained HTTP and then closed the DB pool. When the pool closed first, the
`pg_advisory_unlock` never reached Postgres, so the lock lingered until Postgres
reaped the dead connection — and a standby (or the restarted instance itself)
couldn't become leader until then, so the monitor didn't sweep.

The step-down is now invoked **synchronously in `main` before the pool closes**
(the coordinator's `Stop()` is exported and idempotent), so leadership frees
immediately on a clean stop and the restarted/standby instance takes over on its
next tick — no multi-minute unmonitored window after a deploy. Latent since the
HA work (v0.17.0).

## v0.20.2 — Scheduled PowerShell script runs

PowerShell scripts can now be run on a recurring schedule, just like Ansible
playbooks and scans. The **Schedules** page gains a "PowerShell script (Windows)"
kind: pick a script and a target host or group, set the recurrence, and the
scheduler fires it via the same runner (bounded fan-out, output cap, run history).

Because a scheduled run is unattended (no interactive credential check-out), it
uses only **open-policy** credentials — the same rule the monitor follows. A
scheduled run against a host whose credential is check-out-gated is reported as a
credential failure for that host rather than silently using a gated secret.
Non-Windows hosts in a targeted group are skipped.

## v0.20.1 — Unified Automation page (Ansible playbooks + PowerShell scripts)

The **Playbooks** nav item is now **Automation**, a single page with two tabs:
**Ansible Playbooks** (Linux) and **PowerShell Scripts** (Windows). The Scripts
tab is the UI for the v0.20.0 runner — author/version PowerShell scripts, run them
on one or many Windows hosts or a group (the host picker lists only Windows hosts),
and watch per-host output stream into a live console, with run history and a
drill-down into any past run's captured output.

Each tab appears only if you can author that kind (`Playbook.Edit` /
`Script.Edit`); the old `/playbooks` URL redirects to `/automation`. The Linux
playbook experience is unchanged.

## v0.20.0 — PowerShell script runner for Windows hosts (backend/API)

Run operator-authored **PowerShell scripts on Windows hosts**, the Windows
counterpart to the Ansible playbook runner. Author/version scripts, then run them
on one or many Windows hosts or a group, with streamed per-host output and run
history — all over the existing WinRM path (no new transport, no sidecar; Python
isn't involved). This release lands the backend + API; the unified Automation UI
(Ansible + PowerShell in one place) follows next. Usable now via the API/SDK/CLI.

- **New tables/permissions** (migration `0040`): `winscripts`, `winscript_versions`,
  `winscript_runs`; `Script.Edit` (author/edit) and `Script.Run` (execute), both
  Administrator-only by default, mirroring `Playbook.Edit`/`Playbook.Run`.
- **Execution** runs over WinRM through the jump host, authenticated with each
  host's **vaulted credential honoring its check-out policy** — a check-out/approval
  -gated credential is only used while the requester holds an active check-out.
- **Scalable + safe by construction:** multi-host runs use a **bounded worker
  pool** (one jump connection per host, same cap as the monitor), output is
  **size-capped** (4 MiB, truncation-marked), the script runs on **exactly one**
  WinRM port (TCP pre-probe — never double-executed on port fallback), and each run
  has a bounded timeout. HA-aware: interrupted runs owned by a dead instance are
  reconciled to `failed` on startup.
- API: `GET/POST /scripts`, `GET/PUT/DELETE /scripts/{id}`, `.../versions`,
  `POST /scripts/{id}/run`, `.../runs`, `GET /script-runs/{runId}` (live output).

## v0.19.9 — Windows pending-updates (surfaced in Ask, dashboard, host details)

The WinRM fact collection now also counts **pending Windows updates** and the
security subset, via the Windows Update Agent COM API with an OFFLINE search
(local cache only — no round-trip to Microsoft, the scalable equivalent of
reading cached apt/dnf metadata). The counts land in the same
`updates_available` / `security_updates` inventory fields the Linux path fills,
so the **assistant** (`query_hosts` with `securityUpdatesMin`, `fleet_issues`),
the dashboard issues, and host details report Windows update posture with no
further changes — ask "which Windows hosts have security updates" and it works.

The search is throttled to the hourly inventory cadence (heavier than the live
per-sweep metrics), and the counts are preserved between checks — so it adds no
per-sweep cost and doesn't affect monitoring scalability.

## v0.19.8 — Windows enrollment: persist the WireGuard config (survive reboots)

Fixed a Windows tunnel that worked until the first reboot and then crash-looped.
The enrollment script wrote the WireGuard config to `%TEMP%\fleet.conf`, installed
the tunnel service from it, and then **deleted** the temp file. WireGuard for
Windows' tunnel service reads its config from that path on every start (it does
not copy it into a store), so after a reboot the service could not load its
config — logging `Unable to load configuration from path: …\Temp\…\fleet.conf`
and shutting down repeatedly — and nothing listened on the WireGuard port until
someone reactivated it by hand. No amount of service auto-start/recovery can help
a service whose config file is gone.

The config is now written to a persistent, ACL-locked path
(`%ProgramData%\Fleet\fleet.conf`, restricted to SYSTEM + Administrators since it
holds the private key) and is no longer deleted, so the tunnel reconnects on its
own after a reboot with nobody logged in. Existing Windows hosts must **re-enroll**
to pick up the persistent config (the old temp config is gone).

## v0.19.7 — RDP monitoring: one jump connection per probe (scale parity)

A Windows/RDP probe opened the jump-host SSH connection twice per sweep — once
for the RDP reachability check and once for WinRM fact collection — while an SSH
host opens it once. Since the monitor's worker-pool size is tuned against the
jump host's `sshd MaxStartups`, that doubled the per-host connection cost and
halved effective headroom for RDP hosts at scale.

The RDP branch now opens a single jump connection per probe and reuses it for
both the TCP check and WinRM, so RDP hosts cost the same as SSH hosts and scale
identically under the shared bounded worker pool (the sweep already pages all
hosts via `AllHosts` with no fixed cap). Removed the now-unused
`ProbeTCPViaJump` gateway helper.

## v0.19.6 — Windows onboarding: turnkey enrollment, richer facts, docs

Windows/RDP hosts now onboard with no hand-run configuration and report the same
resource details as Linux hosts.

- **Enrollment script now configures the host end-to-end.** In addition to the
  WireGuard tunnel it enables **Remote Desktop** (opens TCP 3389) and stands up a
  **WinRM HTTPS listener** on 5986 with a self-signed cert and firewall rule, so
  fact collection works over TLS with no manual `Enable-PSRemoting` and no
  `AllowUnencrypted`. Each step is best-effort and prints a summary of what it
  configured. The one manual action remains pasting the printed public key back
  into Fleet.
- **Richer Windows facts.** Fact collection over WinRM now also gathers **disk
  usage per drive, free/used memory, network interfaces, and the default
  gateway**, populated into the same `HostMetrics` the UI already renders — so the
  host details show disk, memory, and primary IP for Windows just like Linux
  (load average stays blank; it's a Unix concept). Metrics refresh every monitor
  sweep.
- **Documented.** The host-enrollment guide has a new **Windows (RDP) hosts**
  section covering the PowerShell the operator runs, the ports involved
  (51820/UDP, 3389, 5986) and who opens them, LAN-vs-remote endpoints, and the
  manual WinRM steps if a stripped host skips the automatic setup.

## v0.19.5 — RDP status: report overlay health (wg_ok)

The RDP/Windows status probe reported online/offline and latency but never set
`wg_ok`, so an enrolled Windows host reachable over the overlay still showed a
"wg down" badge. It now sets `wg_ok` when the RDP port is reached over the
WireGuard address, matching the SSH probe.

(Windows SYSTEM facts — OS, CPU, memory, uptime — are collected separately over
WinRM; if they show "—", WinRM/PSRemoting likely isn't enabled or reachable on
the host. See the enrollment guide.)

## v0.19.4 — Windows enrollment: fixed ListenPort so the jump can reach the host

Supersedes the v0.19.3 approach. A Windows host now enrolls with a fixed
WireGuard `ListenPort` (the configured `FLEET_WG_PORT`, default 51820), exactly
like a Linux host, and the jump keeps a static endpoint to dial it. This is what
lets a host that shares the jump's LAN come up: the jump reaches the host
directly on the LAN, so the tunnel establishes even though the host's own
configured `Endpoint` is the *public* address (a LAN host can't hairpin to its
own public IP). Remote hosts are unaffected — their outbound keepalive to the
public endpoint establishes the tunnel and WireGuard relearns the real endpoint.

Previously the Windows tunnel used a random source port and didn't listen on the
WireGuard port, so the jump couldn't reach it and the tunnel only came up if the
host could dial the public endpoint itself — which fails for a LAN host. The
v0.19.3 roaming change is reverted in favour of this (it had removed the jump's
ability to initiate, which is precisely what makes LAN hosts work).

## v0.19.3 — Windows enrollment: add the jump peer roaming (no static endpoint)

A Windows host enrolls a dial-out WireGuard client that uses a random source
port and never listens on the WireGuard port, so the jump host cannot reach it
at `mgmtAddr:WGPort`. Enrollment previously pinned the jump-side peer to that
(unreachable) static endpoint — correct for a Linux host that listens on the
port, wrong for a dial-out Windows client, and meaningless when the Windows host
is remote behind NAT. The jump peer is now added **roaming** for RDP hosts: the
hub learns the endpoint from the client's keepalive handshake, exactly as it
already does on a jump-host rebuild.

Note: the Windows tunnel dials the jump host at the endpoint baked into its
config (your stored WireGuard endpoint). For a host on the jump's LAN, set the
enrollment endpoint to the jump's LAN address; for a remote host, use the public
endpoint with UDP/WireGuard forwarded to the jump — same as remote Linux hosts.

## v0.19.2 — RDP: don't route over the overlay until the host is enrolled

Clicking **Enroll** on an RDP host allocates and saves the host's WireGuard
overlay address immediately (the enrollment script needs it baked in). But the
RDP connection path preferred that overlay address the moment it was set — and
committed to it with no fallback — so a host mid-enrollment (tunnel not yet up)
became unreachable over RDP even though its direct address still worked.

RDP addressing is now enrolled-aware: the overlay address is used only once the
host is actually enrolled (tunnel established), and connections fall back to the
direct management address otherwise (unless strict WireGuard mode is enabled).

## v0.19.1 — Fix Windows enroll hang + finish-dialog crash

Finishing a Windows overlay enrollment could hang for minutes and then white-screen.
Two fixes: the RDP-over-overlay reachability check now has an 8-second timeout (it was
unbounded, so a still-settling tunnel or a host firewall blocking 3389 stalled the
finish), and the enrollment-result dialog no longer crashes if the response has no
step list (defensive rendering).

## v0.19.0 — Windows WireGuard enrollment (remote reach)

Windows/RDP hosts can now join the WireGuard overlay, so they're reachable from
**anywhere** with internet — the same dial-out model as Linux, previously Linux-only.
On an RDP host, **Enroll** offers a **PowerShell** script: run it elevated on the host
and it installs WireGuard, brings up a persistent dial-out tunnel to the jump host (no
inbound firewall rules), and prints its public key; paste that back and Fleet adds it as
an overlay peer. The RDP session and WinRM fact collection then ride the tunnel.
Enrollment is protocol-aware (bash for SSH hosts, PowerShell for Windows) and, for
Windows, verifies RDP reachability over the new tunnel instead of SSH-cert login.
(WireGuard on Windows is for non-FIPS deployments.)

## v0.18.0 — Windows host facts over WinRM

RDP (Windows) hosts previously showed no inventory (OS/CPU/memory/uptime were blank)
because fact collection runs over SSH, which Windows lacks. The monitor now collects
those facts over **WinRM (PowerShell remoting)**: it authenticates with the host's
attached **open-policy** vault credential and tunnels to WinRM through the jump host
(trying HTTPS `5986` then HTTP `5985`, NTLM), best-effort and refreshed like other
inventory. Requires WinRM enabled on the host. Toggle with `FLEET_RDP_COLLECT_FACTS`
(default on); ports via `FLEET_RDP_WINRM_PORTS`. The host-details dialog now hides
fields that don't apply to Windows (kernel, SSH version, WireGuard, apt/dnf updates).

## v0.17.8 — Revert RDP download to raw recording (.guac)

The self-contained offline RDP HTML player is dropped: guacamole-common-js 1.5.0's
recording playback leaves the desktop black offline (an async image-load race in the
library's render loop that can't be fixed cleanly from outside). The RDP download is
again the **raw `.guac` recording**; in-app replay (Session Replay → Desktop) remains
the supported way to watch. Removes the vendored player and its endpoint.

## v0.17.7 — Downloaded RDP player: patch the Guacamole Blob bug

The downloaded player threw `cannot read property "size" of undefined` — a bug in
guacamole-common-js 1.5.0's `SessionRecording` Blob support (it calls its Blob parser
with an unassigned `recordingBlob`). The vendored library is patched to assign
`recordingBlob = source`, so the player replays the recording from the embedded Blob
directly (original bytes, no fetch/tunnel). Backend-only.

## v0.17.6 — Downloaded RDP player: play from a Blob

Second attempt at the downloaded-player black screen: the recording is now fed to
`Guacamole.SessionRecording` directly as a `Blob` (parsed and rendered in place) rather
than through a streaming tunnel, whose reconstruct-then-render path dropped large
desktop-image draws offline while the small cursor draws survived. Backend-only.

## v0.17.5 — Fix black screen in the downloaded RDP player

The downloaded self-contained RDP player showed only a moving cursor on a black screen
(the desktop image draws were lost) even though in-app playback rendered correctly. The
embedded recording was served to the player via a large `data:` URL, which browsers
deliver/stream differently (notably under `file://`); it is now served via a `blob:`
URL — a real, chunk-streamed resource identical to the in-app playback path.
Backend-only.

## v0.17.4 — Self-contained RDP recording player

The RDP recording download is now a **self-contained HTML player** (double-click to
watch offline, no server) — full parity with SSH replay export. The Guacamole client
and the recording are both embedded; the player loads the library via a blob-URL
dynamic import and replays through the same streaming path as in-app playback. The
Guacamole client (v1.5.0) is vendored into the backend for embedding.

## v0.17.3 — Download button for RDP recordings

Session Replay → Desktop (RDP) recordings gained a **download** action (initially the
raw `.guac` recording; superseded by the self-contained HTML player in v0.17.4).

## v0.17.2 — Fix white screen when opening an RDP recording

Opening an RDP recording in Session Replay crashed the page to a white screen
(`Node.removeChild: The node to be removed is not a child of this node`). The player's
canvas container also held a React-managed loading spinner, so React reconciled
against the manually-inserted Guacamole canvas and threw. The canvas now lives in its
own React-inert node with the spinner as an absolutely-positioned sibling (matching the
live desktop viewer). Frontend-only.

## v0.17.1 — Fix RDP recording playback

RDP session recordings failed to play back ("Could not download the recording",
Play greyed out) even though the recording file was valid. The player downloaded the
recording as a Blob and used `Guacamole.SessionRecording`'s block-sliced Blob parser,
which mis-parses the stream. Playback now streams the recording through a Guacamole
tunnel (the reference-player approach) via a new token-authenticated endpoint
(`GET /rdp/recordings/{id}/stream`). No migration; rebuild the backend + frontend.

## v0.17.0 — High Availability (multi-instance)

Fleet Terminal can now run as **multiple backend instances** behind a load balancer,
for redundancy and rolling upgrades. HA is **safe by default** — a single-instance
deployment is unchanged (it is simply always the leader). See the new
[High Availability guide](high-availability.md).

- **Leader election & instance identity.** Each backend registers a heartbeat and
  contends for leadership via a Postgres session-scoped advisory lock (auto-releases
  on failure → no split brain). Cluster-wide singleton jobs (host monitor, KRL
  distribution, retention, digests, reports, backups, dynamic groups) run only on the
  leader; per-instance work still runs everywhere.
- **Ownership-scoped reconciliation.** Long-running rows (sessions, scans,
  playbook/vuln/remediation/enrollment runs) are tagged with their owning instance.
  On boot and periodically, only work abandoned by a **dead** instance is failed —
  never a live peer's. Fixes the pre-HA "kill everything on restart" behaviour.
- **Cross-instance real-time.** A Postgres LISTEN/NOTIFY backplane bridges the
  WebSocket hub so dashboard events reach clients on every instance, and an admin can
  terminate a session whose live terminal runs on another instance.
- **Issue-own-cert model.** A request landing on an instance that doesn't hold the
  session's key mints its own short-lived cert and **never revokes a peer's** — so any
  request can be served by any instance (no sticky sessions required). A dead
  instance's now-keyless certs are revoked by a leader sweep.
- **Postgres-failover-ready pool** (idle-conn recycling + exponential-backoff
  reconnect) and a **standby jump-host path**: each host's WireGuard public key is now
  persisted, and `fleetctl wg-peers` emits the overlay peer list so a standby jump
  host can rebuild the hub from the database on failover.
- **Cluster roster** on the Background Jobs page (instances, leader, liveness).

*Deploy:* no configuration is required for single-instance. Migrations `0036`–`0039`
apply automatically. For a multi-instance deployment (shared Postgres + shared storage
for recordings, a VIP for the jump host), follow `docs/high-availability.md`.

**Also in this release — RDP refinements.**

- **Windows hosts show real status.** RDP hosts are now health-checked with a TCP probe
  to the RDP port through the jump host (they have no SSH for the standard probe), so
  they report online/offline instead of always "unknown".
- **Protocol-aware actions.** RDP hosts only show actions that work on them — a
  **Desktop** button in place of Terminal/SFTP across the Hosts, Terminals, and
  Dashboard views, and the SSH-only actions (OpenSCAP scan, support bundle, WireGuard
  enrollment) are hidden for RDP hosts.
- **RDP connection failures are logged.** The broker now logs the reason a desktop
  session fails to start (credential, reachability, guacd, handshake) instead of only
  closing the browser tab.
- **guacd runs with a writable `HOME`** (also shipped as v0.16.2) so FreeRDP's TLS/NLA
  setup works.

## v0.16.0 — RDP recording, clipboard/display controls & file transfer

Rounds out Windows/RDP (v0.15.0 shipped live desktops) with recording/replay,
per-host display & security controls, gated clipboard, and drive-redirection file
transfer.

**Session recording & replay.** Every RDP session is recorded (guacd streams a
Guacamole recording to a shared volume; the backend stores metadata and serves it
back). A new **Desktop (RDP)** tab under **Session Replay** replays them with a
built-in player (play/pause + seek), gated by `Session.Replay`; delete/prune needs
`System.Configure` and shares the SSH recording retention window. Sessions now audit
`session.rdp_end` (with duration) alongside `session.rdp_start`.

**Clipboard & display/security controls.** Per-host RDP options passed to guacd:
security mode (Any / NLA / TLS / RDP / Hyper-V), color depth, resolution/DPI, AD
domain, and audio + wallpaper/theming toggles — for compatibility with locked-down /
NLA-only Windows hosts. **Clipboard** copy (desktop → browser) and paste (browser →
desktop) are independent and **off by default** (a data-transfer surface); guacd
enforces each gate and enabled directions are audited. (Clipboard needs an HTTPS
origin.) The live desktop also resizes to follow the browser window.

**Drive redirection (file transfer).** Enabling **Enable drive** mounts a **Fleet**
drive in the session and adds a **Files** button to the viewer — browse, download, and
upload. **Allow upload / Allow download** are independent and off by default. Each
session gets an isolated exchange directory on the shared `rdp-drive` volume that the
backend removes when the session ends (scratch space, not durable storage).

*Multi-monitor is not supported* — Guacamole's web client cannot drive multiple RDP
displays.

*Deploy:* pull the updated `deploy/compose/docker-compose.yml` — the **guacd** sidecar
now runs as the backend's `fleet` user (uid 100 / gid 101) and mounts the shared
`recordings` and `rdp-drive` volumes. Optional `FLEET_RDP_DRIVE_DIR` defaults to
`/var/lib/fleet/rdp-drive`. Migrations `0034` (the `rdp_recordings` table) and `0035`
(a JSONB `rdp_options` column on hosts) apply automatically.

## v0.15.0 — Windows desktops (RDP)

Fleet brokers full **Windows desktop (RDP)** sessions to the browser, alongside SSH
terminals and SFTP — no local RDP client, no direct route to the host.

- **Live RDP in the browser.** Set a host's **Protocol** to **RDP** and pick its port
  (default `3389`); the host then shows a **desktop** action that opens the live
  Windows desktop in a new tab, gated by `Host.Connect` and the usual per-host access
  checks. Mouse and keyboard are wired through; each connect is audited
  (`session.rdp_start`).
- **Brokered through the jump host.** The backend tunnels the target's RDP port over
  the **same jump-host / WireGuard path as SSH** and hands the bundled **guacd**
  sidecar an ephemeral local proxy — so guacd only ever connects back to the backend
  and needs no route to managed hosts.
- **Credential injected, never seen.** RDP authenticates with a **vaulted password
  credential** injected into guacd **in memory** — the operator never sees it and it
  never reaches the browser. Attaching it enforces the same `Host.Edit` +
  credential-access (and check-out policy) rules as SSH injection.

*Deploy:* add the `guacd` service (bundled in `deploy/compose/docker-compose.yml`) to
your stack. Optional `FLEET_GUACD_ADDR` / `FLEET_RDP_PROXY_HOST` default to the
compose service names. Migration `0033` (host `protocol` + `rdp_port`) applies
automatically. Clipboard, drive redirection, multi-monitor, and RDP session recording
are not in this release.

## v0.14.0 — Credential vault: injection, check-out, rotation

The credential vault becomes a full PAM workflow: connect through credentials
without seeing them, gate high-value ones behind approved check-out, and rotate
them.

- **Credential injection (connect without seeing the secret).** On a host's edit
  form, set **Authentication** to a vault credential (password or SSH key). When
  anyone opens a terminal or SFTP to that host, Fleet decrypts the credential **in
  memory** and authenticates the connection with it — the operator never sees the
  secret, and it never reaches the browser. Use it for appliances, network gear, and
  legacy systems that can't accept Fleet's ephemeral certificates. Attaching a
  credential requires `Host.Edit` plus access to it; injected sessions are audited.
- **Check-out & approval.** Each credential has an **access policy**: *open* (reveal/
  inject per grants), *check-out required* (time-boxed, self-service), or *approval
  required* (a `Credential.Approve` holder — not the requester — approves each
  check-out; the classic four-eyes control). Reveal **and** injection are blocked
  until an active check-out is held; approvers get an inbox on the Credentials page.
- **Rotation.** For a password credential attached to a host, **Rotate**
  (`Credential.Rotate`) changes it automatically over SSH, verifies the new login,
  and stores it — reverting if the host change fails so the vault stays consistent.
  Requires passwordless `sudo chpasswd` on the host; validate against a test host
  before production use.

*Deploy:* migrations `0031` (host auth method) and `0032` (check-out + the
`Credential.Approve` permission) apply automatically.

## v0.13.0 — Credential vault

Fleet is now a secrets manager, not just an SSH-certificate broker.

- **Credential vault.** A new **Credentials** page stores static credentials —
  **passwords, SSH keys, API keys** — for systems that can't use Fleet's ephemeral
  certificates (network gear, appliances, databases, legacy hosts). Secret material
  is **encrypted at rest** with secretbox under a dedicated **`FLEET_VAULT_PASSPHRASE`**
  (required in production and enforced to differ from the CA passphrase; falls back
  to it in development).
- **Audited reveal.** Revealing a credential's plaintext requires the `Credential.View`
  permission (or `Credential.Manage`) plus access to that specific secret, and is
  **always written to the audit log**. Secret material never appears in logs.
- **Per-secret grants.** Delegate access to a credential to a user or group at
  **view / use / manage** level without granting vault-wide management. Administrators
  hold `Credential.Manage`; Operators get view/use/rotate; **Auditors are excluded
  from reveal**.
- **Versioning.** Editing a credential's value stores a new version, keeping rotation
  history.

*Deploy:* migration `0030` (vault tables + `Credential.*` permissions) applies
automatically. To use the vault in production, set `FLEET_VAULT_PASSPHRASE` to a
strong value distinct from `FLEET_CA_PASSPHRASE`.

## v0.12.1 — Fix: ZFS ARC memory accounting

- **Memory usage on ZFS-on-Linux hosts is no longer overstated.** The ZFS ARC cache
  is charged as "used" memory and excluded from the kernel's `MemAvailable`, even
  though it is reclaimable under pressure. The metrics collector now reads
  `/proc/spl/kstat/zfs/arcstats` and adds the reclaimable ARC (`size − c_min`) back
  to available memory, so a host with a large cache no longer reads as near-
  exhaustion (and the "high memory" insight clears accordingly). Non-ZFS hosts are
  unaffected.

*Deploy:* rebuild the backend; corrected values appear on the next monitor sweep.

## v0.12.0 — Terraform provider

Manage Fleet as infrastructure-as-code.

- **`terraform-provider-fleet`** — a Terraform provider (built on the modern plugin
  framework and the Go SDK) that manages **hosts**, **groups** (including dynamic
  membership rules), **service accounts**, and their **API tokens** declaratively,
  plus a `fleet_role` data source to resolve role names to IDs. It authenticates with
  the same service-account token as the SDK and CLI; hosts and groups support full
  CRUD and `terraform import`. See the provider's README and `examples/` for usage,
  installation via dev overrides, and current limitations.
- The Go SDK gains `GetGroup` and `GetServiceAccount` (read-by-id) helpers.

*Note:* the provider builds from the repository (it references the in-repo SDK);
publishing it to the Terraform Registry is a separate release step.

## v0.11.0 — Assistant actions: guarded actions with approval + action policy

Completes the actionable assistant: it can now propose consequential actions that
require a second person to approve, and administrators can govern what it may do.

- **Guarded actions require approval.** More consequential actions the assistant can
  propose — **disable a user** and **delete a host** — never run on the requester's
  confirm. They show **Request approval** and wait for a different administrator (with
  the new `Assistant.Approve` permission) to approve or deny. Separation of duties is
  enforced: the requester can never approve their own action. On approval, Fleet
  **re-checks that the original requester still holds the required permission and an
  active account** before running it — an approval is not a bypass. Approvers see an
  "Awaiting your approval" inbox on the Ask page and a badge in the sidebar; every
  decision is audited and notified.
- **Action policy.** Under **Settings → Assistant actions**, administrators can
  **require approval for every assistant action** (even the safe ones) or **disable
  specific actions** entirely. Policy is applied when an action is proposed.
- **Action history.** The Ask page now shows a collapsible history of your recent
  assistant actions and their outcomes.

*Deploy:* migration `0029` (approval columns + the `Assistant.Approve` permission,
granted to Super Administrator and Administrator) applies automatically.

## v0.10.0 — Actionable AI assistant: docs answers + confirmed actions

The "Ask Fleet" assistant gains two capabilities, built so it can never act without
explicit human confirmation.

- **Answers grounded in the documentation.** Ask how-to and conceptual questions —
  *"how do I configure SAML?"*, *"how do access reviews work?"* — and the assistant
  searches the product documentation and answers with clickable **Sources** that link
  into the in-app help. Retrieval is a lightweight, dependency-free keyword (BM25)
  index over the docs embedded in the backend; no external service or model is added.
- **Proposed actions you confirm.** With the new `Assistant.Act` permission, the
  assistant can *propose* a small set of safe actions — currently **run a vulnerability
  scan** on a host or group, and **add/remove tags** on a host. The assistant never
  runs anything itself: it stages a proposal, you see exactly what will happen, and it
  executes only when you click **Confirm**. Execution **re-checks your permission and
  host access at that moment**, so the assistant can never do anything you couldn't do
  yourself or didn't approve. Every action is audited, and the proposal history is
  retained.

Security model: the model proposes, a human authorizes, and the backend executes and
re-verifies. Untrusted text (host data, documentation) is treated as information to
report, never as instructions to act on. Actions are gated behind `Assistant.Act`
(granted to Super Administrator, Administrator, and Operator) on top of the per-action
permission.

*Deploy:* migration `0028` (assistant action proposals + the `Assistant.Act`
permission) applies automatically. No configuration change is required beyond enabling
the assistant under Settings → AI assistant as before.

## v0.9.1 — Fixes: scans on symlinked hosts, session-expiry UX

- **Vulnerability scans no longer fail on hosts that symlink `/etc/os-release`.** The
  on-host collector now dereferences symlinks when building the package archive, so
  hosts where `/etc/os-release` (or `/var/lib/rpm`) is a symlink — common on NAS /
  appliance and openSUSE systems — scan correctly instead of failing with
  "links not allowed in archive".
- **Expired sessions now return you to the login screen.** When a background token
  refresh fails (the session expired or was reaped by the idle / absolute timeout),
  the UI clears the session and redirects to login instead of leaving you on a page
  whose actions all fail with "missing access token". The backend already enforced the
  expiry server-side; this closes the client-side display gap.
- **The vulnerability-scan dialog now shows the scanner's actual error** instead of a
  generic message.

*Deploy:* rebuild the backend and frontend images.

## v0.9.0 — Access certification, automation SDK/CLI, and SAML + SCIM

Three enterprise capabilities: certify access on a schedule, manage Fleet as code,
and federate identity with SAML SSO and SCIM provisioning.

- **Access certification (access reviews).** Create recertification campaigns that
  snapshot the current access grants — each user's group memberships and direct host
  grants — then **keep or revoke** each one and export the sign-off as CSV audit
  evidence. Revoking removes the underlying grant. Scope a review to everyone, one
  group, or specific users; a due date and progress are tracked. Gated by a new
  `AccessReview.Manage` permission (granted to Super Administrator, Administrator,
  and Auditor).
- **Automation: Go SDK + `fleet` CLI.** A standalone, dependency-free Go module
  (`github.com/your-org/Fleet-Terminal/sdk`) and a token-authenticated `fleet`
  command-line tool for managing hosts, groups (incl. dynamic rules), users, roles,
  service accounts and tokens, vulnerability scans, and CSV reports — for CI/CD,
  scheduled jobs, and custom tooling. Authenticates with a service-account `flt_`
  token; distinct from the on-host `fleetctl` recovery tool. See the new
  **Automation** guide.
- **SAML 2.0 single sign-on.** Authenticate users against a SAML identity provider
  (Okta, Azure AD / Entra ID, OneLogin, ADFS…), in addition to OIDC and LDAP. Both
  SP-initiated and IdP-initiated flows; IdP-signed assertions are validated
  (signature, audience, time bounds) before trust. Just-in-time user provisioning is
  gated by an auto-create toggle. The SP metadata, ACS, and entity-ID URLs are shown
  in the config UI.
- **SCIM 2.0 provisioning.** Let your identity provider create, update, and
  **deprovision** Fleet accounts automatically — disabling an account (and tearing
  down its live sessions and credentials) the moment a user is removed upstream.
  Users create/read/replace/PATCH/delete plus discovery endpoints, authenticated by a
  dedicated, revocable `scim_` bearer token. Pairs with SAML SSO.

*Deploy:* migration `0027` (access reviews) applies automatically. No configuration
change is required; SAML and SCIM are off until configured under Settings →
single sign-on / provisioning.

## v0.8.2 — Fixes: in-app help and CVE database

Two defect fixes for the in-app documentation and the vulnerability scanner.

- **In-app Help no longer renders blank.** The searchable help bundle is generated
  from the documentation at image-build time; the frontend image now builds with the
  docs present in its context, so Help shows its guides instead of a blank page. The
  build now fails fast if the help content is missing rather than shipping it empty,
  and the Help page degrades to a clear message if a bundle is ever absent.
- **CVE database update/import fixed.** The scanner could not create its database
  directory when running as its unprivileged user, so both the online update and the
  offline import failed with a permission error. The scanner image now creates that
  directory with the correct ownership, and the update error in the UI now shows the
  scanner's actual message instead of assuming a connectivity problem.

*Deploy:* rebuild the frontend and scanner images. If the CVE database volume already
exists from a prior deploy, correct its ownership once —
`docker compose exec -u root grype-scanner chown -R 10001:10001 /home/scanner/.cache/grype`
(or remove and recreate the `grype-db` volume) — then update the database from the
Vulnerabilities page.

## v0.8.0 — Vulnerability scanning

CVE vulnerability scanning of managed hosts, distinct from the OpenSCAP compliance
scans.

- **Vulnerability scanning (Grype).** Scan a host or a whole group for known-
  vulnerable packages and get per-host findings with **CVSS scores** (CVE, package,
  installed vs. fixed version, severity, score). A new `grype-scanner` sidecar does
  the matching centrally; the backend reads each host's package database over SSH, so
  **nothing is installed on managed hosts**. CVSS is populated even on Debian/Ubuntu
  (enriched from the associated NVD records).
- **Vulnerabilities page** with a fleet roll-up (highest CVSS and severity counts per
  host) and a drill-in findings table. Scans run on demand or on a schedule, findings
  are alertable and exportable to CSV, and results are audited.
- **CVE database management** — **Update online** when the backend has internet, or
  **Import offline** a pre-downloaded database archive for air-gapped deployments. The
  database build date is shown.

*Deploy:* adds the `grype-scanner` container (rebuild the stack) and migration `0026`.
Load the CVE database once from the Vulnerabilities page before the first scan.

## v0.7.0 — Enterprise integration

Seven capabilities that close common enterprise/PAM gaps.

- **Service accounts & API tokens.** Non-human identities for automation (CI/CD, IaC,
  monitoring) that carry roles and host access like a user but authenticate via hashed,
  optionally-expiring `flt_` bearer tokens — and survive employee turnover. Managed on a
  new Service Accounts page.
- **Compliance reporting.** Export access, audit, certificate, and scan-posture
  evidence as CSV over any date range from a new Reports page, and schedule recurring
  reports delivered as CSV email attachments.
- **Live session shadowing.** Watch an active terminal session in real time, read-only,
  for four-eyes oversight; watching is itself audited.
- **MFA recovery codes.** One-time backup codes as a fallback for a lost authenticator
  or passkey, generated self-service in Security settings.
- **Broader alerting.** Native PagerDuty and Opsgenie incident channels (severity-gated)
  and a Microsoft Teams webhook format, alongside email and generic webhooks.
- **Dynamic host groups.** Group membership can follow a rule over host attributes
  (environment, tags, OS, hostname); matching hosts join automatically.

*Deploy:* migrations `0022`–`0025`.

## v0.6.2 — Correct version stamping

- The deployed build now reports its real release version (from git tags) instead of
  `dev`, and the release tooling keeps version tags in sync across mirrors.

## v0.6.1 — Host-flapping fix

- Fixed hosts intermittently showing offline after v0.6.0: the health-check sweep was
  parallelized too aggressively for the jump host's SSH limits. Sweep concurrency is now
  bounded (configurable via `FLEET_MONITOR_CONCURRENCY`, default 6).

## v0.6.0 — Hardening and a deeper Ask AI

A security/reliability hardening pass plus a much-expanded AI assistant.

- **Ask AI upgraded** from a single-shot question box into a fleet-health assistant:
  multi-turn conversation memory (follow-up questions), a **fleet-insights** engine
  (offline hosts, low disk, capacity/disk-runway projection, high load, pending
  updates) surfaced on the dashboard and to the assistant, and opt-in **scheduled
  fleet-health digests**.
- **Reliability & security fixes:** a browser-terminal crash/DoS race, an OIDC
  account-binding weakness, silent 1000-host caps in monitoring and certificate-
  revocation distribution, configurable data/audit **retention**, atomic scheduler
  claims, bounded scan/playbook output, backup and audit-forwarding hardening, and an
  atomic first-run bootstrap.

*Deploy:* migration `0021` (host metric history); new optional retention/monitor
settings.

---

For releases prior to v0.6.0, see the Git history and the GitHub Releases page.
