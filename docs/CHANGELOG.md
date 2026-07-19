# Changelog

Notable changes to Fleet Terminal, newest first. Dates are release dates. Database
schema migrations apply automatically on startup; deploy notes call out anything else.

---

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
  (`github.com/kforbus3/Fleet-Terminal/sdk`) and a token-authenticated `fleet`
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
