# Operations Guide

Day-to-day operator flows for Fleet Terminal. Assumes the stack is up via `make up`.

## First run

1. `make up` — starts Postgres, Redis, backend, frontend, and the local SSH test fabric
   (jump host + Ubuntu/Rocky managed hosts with userspace WireGuard).
2. Open the frontend (http://localhost:5173). The **bootstrap wizard** appears on first run;
   create the initial Super Administrator. The wizard then permanently self-disables.
3. `make trust` — seeds the test-fabric nodes with the backend's SSH CA public key so they
   trust issued certificates. In production this trust is established during enrollment over a
   bootstrap credential; in the local fabric we seed it directly. Re-run after any fresh `make up`.

## Adding & enrolling a host

1. **Hosts → New Host**. Provide:
   - **Hostname** (required)
   - **Address** — the management address used to reach the host during enrollment
     (test fabric: `172.30.0.21` for `host-ubuntu`, `172.30.0.22` for `host-rocky`)
   - **WireGuard Address** — leave blank to **auto-assign** the next free overlay address, or
     type a specific one (validated to be in the overlay subnet and not already used)
   - **SSH user** — `fleet` for the test fabric
2. Click the **Enroll** (cable) icon on the host row and choose how to reach the host for the
   one-time bootstrap (all install CA trust + WireGuard; full detail in the
   [Host Enrollment Guide](./host-enrollment-guide.md)):
   - **SSH password** — brand-new/existing host with no prior setup (root or a sudoer + password).
   - **SSH private key** — host with password auth disabled; paste a key already in `authorized_keys`.
   - **SSH agent** — run the `fleet-enroll-agent` bridge from your laptop; the key never leaves it.
   - **No install (ssh-pipe)** — run a one-liner in your own terminal (`curl … | ssh host sudo bash`),
     then paste the printed host public key into the Finish step. No install, no key upload.
   - **Already trusts the Fleet CA** — re-provision a previously-enrolled host with the session cert.
   The password / pasted key is used once and never stored.
3. Enrollment, over SSH:
   - reads the jump host's WireGuard key,
   - (password bootstrap) installs `/etc/ssh/fleet_ca.pub`, the login user + sudo + principal
     mapping, and the sshd drop-in, then reloads sshd,
   - installs WireGuard tooling if missing (apt/dnf/yum/apk),
   - generates the host's WireGuard keypair **on the host** (private key never leaves it),
   - brings up `wg0` (kernel module, or userspace `wireguard-go` fallback) and writes
     `/etc/wireguard/wg0.conf`,
   - registers the host as a peer on the jump host (the VPN server),
   - **verifies per-user certificate login** through the jump host.
   A dialog streams each step and shows the assigned overlay address.

> WireGuard address pool and endpoints are configured via `FLEET_WG_SUBNET`,
> `FLEET_WG_JUMP_IP`, `FLEET_WG_JUMP_ENDPOINT`, and `FLEET_WG_PORT`.

## Granting host access

Users have no host access by default. Grant it via the host row's **Manage access** (lock)
icon:

- **Groups** — add the host to a group; any member of that group can reach it.
- **Individual users** — grant a single user direct access to this host.

Access grants control *whether* a user can reach a host; the **`Host.Sudo`**
permission (on their role) controls *what they get on it* — root via sudo, or a
**login-only** shell with no sudo. See the Administrator Guide for the two-account
model. (Hosts enrolled before this feature need a re-enroll to gain the
login-only account.)

Review access at a glance: **Manage access** lists a host's groups + direct users, and a
user's **View accessible hosts** action (Users page) lists every host they can reach. Users
without standing access can request **Just-in-time** access (below).

## Connecting a terminal

Use the **Terminals** page for a quick-connect launcher: search your accessible hosts and click
**Terminal** (or **Files**). You can also click the **terminal** icon on a host row, or navigate
to `/terminals/<hostId>`. The browser opens a WebSocket to the backend — the only SSH client —
which dials the host through the jump host using a **certificate unique to that (user, host)
pair**. The session is recorded (replay under **Session Replay**) and audited.

## Watching a live session

For four-eyes oversight of privileged access you can **shadow** an active session —
read-only, in real time.

1. Open **Session Replay** and find an **active** session.
2. Click **Watch live** — a full-screen, read-only terminal opens and renders at the
   operator's exact size, mirroring their output as it happens.
3. Close the viewer to stop watching.

You need the **`Session.Watch`** permission (Super Admin, Administrator, Auditor by
default). Watching sends **no keystrokes** — it is strictly one-way — and is
**itself audited** (`session.watch`), so oversight is accountable. This is live
shadowing; recorded **replay** of finished sessions is on the same page.

## Transferring files (SFTP)

Click the **folder** icon on a host row (or `/files/<hostId>`). Browse directories, download
files, and upload (button or drag-and-drop). Every transfer is brokered by the backend and
recorded in the audit log.

## Dashboard

The home page is an at-a-glance, actionable overview (each panel shown only if you have
permission for its data): stat cards (hosts + online, active sessions, pending approvals)
that link to the full page, **quick connect** to your hosts, **recent audit activity**, and
hosts that **need attention** (offline). A **Live sessions** panel shows, in real time, which
users are connected to which hosts — the terminal broadcasts session start/end over the
WebSocket hub, so it updates as people connect and disconnect (needs `Session.Replay`).

## Live monitoring

The monitor runs authenticated SSH health checks (no ICMP) against enrolled hosts every 30s,
updating status (online/offline/unknown), latency, uptime, and WireGuard handshake freshness.
The dashboard subscribes to a WebSocket and updates in real time.

During the same check it also re-collects **host facts** — distro + version, kernel,
architecture, CPU count, memory, and SSH version — but at most once an hour per host (over the
already-open connection, so it adds no extra SSH dials). Every probe also captures **resource
metrics**: disk usage per filesystem, memory used, load average, and network facts (interfaces,
primary IP, default gateway). View them per host via the **Details** (ⓘ) button on the **Hosts**
page (a "Resources" section), which fetches that single host on demand.

## Pending package updates

During the hourly facts pass the monitor also collects each host's count of **available package
updates** — apt or dnf, with the **security-only** subset broken out — read from the host's
cached package metadata (no extra SSH dials, no network refresh on the host). View it per host
via the **Details** (ⓘ) button on the **Hosts** page ("Updates available", shown as
`N (M security)`). The AI assistant can answer about it too (below).

## Filtering by group

The **Hosts** and **Terminals** pages have a **Filter by group** multi-select — pick one or more
groups to narrow the list to their member hosts.

## Dynamic groups

Instead of adding hosts to a group by hand, give the group a **rule** and matching hosts join
automatically (and their members' access follows):

1. **Groups → New/Edit group → rule editor**. Set any of: **environment** (exact), **tags — all
   of** / **tags — any of**, **OS contains**, **hostname contains**.
2. Save. Matching hosts populate immediately, and membership **auto-reconciles** as hosts change
   or new ones enroll (recomputed on save and every ~3 minutes).
3. To go back to hand-picked membership, **clear the rule** — the group becomes **Manual** again.

The Groups page badges each group **Dynamic** or **Manual** and summarizes the rule.

> On a **Dynamic** group, **manual add/remove is disabled** — Fleet refuses it so membership
> always reflects the rule. An **empty rule matches no hosts** (it is not "all hosts"). Live
> metrics are intentionally not rule inputs, so membership won't flap.

## AI assistant (Ask Fleet)

An optional, **local-only** assistant answers natural-language questions about the fleet —
"which hosts have less than 20% disk free?", "offline debian hosts", "prod hosts under heavy
load", "hosts with pending security updates". It's **read-only**: a local Ollama model
translates the question into a curated query, the backend runs it (scoped to data *you* can
access) and shows the **actual matching results** beside the answer — no data leaves your
network, and every question is audited. Beyond host data and active sessions, it can also report
**pending package updates** and **recent security scans and playbook runs** — including whether
each was **scheduled or run manually** (recent runs need `Playbook.Run`).

**Enable it (admin):** **Settings → AI assistant** — turn it on, enter your Ollama URL
(e.g. `http://ollama.internal:11434`), click **Load models**, pick a model, **Save**. Then users with
the `Assistant.Use` permission get an **Ask** item in the sidebar. The assistant never runs
commands or changes anything; treat answers as a starting point and verify before acting.

## Two-factor authentication (TOTP / passkeys)

1. **Security → Set up authenticator**. **Scan the QR code** (generated in the browser, so the
   secret never leaves the machine) or enter the secret key manually, then enter the current
   6-digit code to confirm. Passkeys (WebAuthn) can be registered from the same page.
2. Subsequent sign-ins prompt for the code after the password step.
3. Remove a factor from the same page. (Admins can reset a locked-out user's factors.)

**Recovery codes.** From the same **Security** page, once a second factor is confirmed, generate
**10 one-time backup codes** for when your authenticator is lost. They are shown **once** — save
them offline. Type one (format `xxxx-xxxx-xxxx`) at the normal MFA prompt in place of a code.
Generating a new set invalidates the old one, and each code works once.

**Requiring MFA.** MFA is optional by default. Admins can enforce it globally
(**Users → Require MFA for all**) or per user (Users → Edit → *Require MFA*). When required and
a user has no factor, their next sign-in walks them through enrollment before any session is
issued — no separate setup step needed.

## Single sign-on (SSO)

Fleet can authenticate users against an external identity provider as well as
local accounts. Every user has an **`auth_source`** (`local`, `oidc`, or `ldap`);
externally-backed accounts can't use a local password. Configure either under
**Settings** (admin / `System.Configure`).

**OIDC (Okta, Azure AD, Google Workspace, Keycloak, Authentik):** **Settings →
Single sign-on (OIDC)**. Enter the **issuer URL**, **client ID**, **client
secret** (stored encrypted), and — usually leaving the defaults — the scopes
(`openid`/`profile`/`email`) and username/email/groups claims
(`preferred_username`/`email`/`groups`). Set a **default role** for new users,
optionally turn on **auto-provision**, add **group → role mappings** (one
`idpGroup=FleetRole` per line), and set the **button text**. In your IdP, set the
redirect/callback URL to **`<PublicURL>/api/v1/auth/oidc/callback`**. Once enabled,
the login page shows a **"Sign in with SSO"** button; clicking it runs the
auth-code + PKCE flow, and first-time users are matched by username then email (and
auto-provisioned if enabled), with group mappings applied on top of the default
role.

**LDAP / Active Directory:** **Settings → LDAP / Active Directory**. Enter the
**server URL** (`ldap://` or `ldaps://`), optional **StartTLS**, a **bind DN** +
**bind password** for a read-only service account (stored encrypted), the **base
DN**, and a **user filter** (`%s` = username, e.g. `(sAMAccountName=%s)`). Map the
**username/email/display-name/groups** attributes, pick a **default role**, and
add **group → role mappings** (`GroupCN=FleetRole`). Directory users sign in on the
**normal sign-in form** — Fleet **falls back to LDAP when local auth fails**,
looks the user up with the service account, then verifies the password by binding
as the user's own DN, provisioning the account (and applying group mappings by CN)
as needed.

See the Administrator Guide for full field details and endpoints.

## Service accounts & API tokens (automation)

For CI/CD, IaC, or monitoring that calls the **REST API**, use a **service account** — a
non-human identity with **no password** (it can't log in interactively or via SSO) that carries
roles and groups like a user and shows up in the audit log as the actor.

1. **Service Accounts** page (needs `ServiceAccount.Manage`). **Create** an account with a name,
   the **roles** it needs, and the **groups** for its host access — least-privilege. (You can
   only grant roles whose permissions you hold yourself.)
2. Open its **token manager** and **create a token**: name it, pick an **expiry** (30/90/365 days
   or never), and **copy the secret now** — it is shown **once** and stored only as a hash.
3. Use it as `Authorization: Bearer flt_…` against the API. **Revoke** a token any time from the
   same panel (effective immediately); disable or delete the account to retire it.

> A token is **REST-only** — it **cannot** open the terminal or SFTP WebSocket (those need an
> interactive session). It is never implicitly super-admin; it has exactly the account's roles
> and groups. Store secrets in your automation's secret manager, not in source.

## Security scans (OpenSCAP)

Click the **shield** (ⓗ) icon on a host row to run an OpenSCAP compliance scan. It needs
`Host.Scan` **and** access to that host (the same group/direct/temporary gate as terminals;
super admins bypass). Pick a **profile** — the dialog discovers the profiles available on the
host (CIS, STIG, PCI-DSS, …) and defaults to the standard baseline — then **Run scan**.

- The profile list only populates once the scanner is installed on the host. On a host that's
  never been scanned, click **Install scanner** (or just run the default profile, which installs
  it) — the list fills in once it's ready.
- The backend runs `oscap` over the gateway as the privileged host account, **auto-installing
  the scanner + SCAP content** if missing (so the first scan on a host can take a few minutes).
- Strict profiles (e.g. **ANSSI High**) run many filesystem-walking checks and can take **tens of
  minutes** on a busy host (the cost is the number of files in users' home directories, not bytes).
  Fleet caps a scan at the **scan timeout** — adjust it in **Settings → Security scans** (5–480 min;
  overrides the `FLEET_SCAN_TIMEOUT` default of 60m). Raise it for hosts with very large
  filesystems, or use a lighter profile for routine checks.
- Alternatively, tick **"Skip slow filesystem rules"** in the scan dialog to exclude the
  filesystem-walking rules (home-dir ownership/permissions, world-writable/SUID/SGID/unowned-file
  audits) — High then finishes in minutes. An advanced field accepts additional rule IDs to skip.
  Skipped rules are excluded from the scan and its score (`oscap --skip-rule`).
- Scans run in the background; the history list updates as they finish, showing the **score**
  and pass/fail counts.
- **View** opens the full HTML report in a sandboxed in-app viewer; **Download** saves it for
  offline viewing. Reports are stored under `FLEET_SCAN_DIR` (`/var/lib/fleet/scans`).

### Remediating failures

On a completed scan with failures, **Remediate** (needs `Host.Remediate`, admin-only by default)
lists the failed rules so you can **select which to fix**:

- **Preview** shows the exact bash `oscap` would run for the selected rules — review before applying.
- **Apply** generates the fixes on the host, runs them under sudo, then **re-scans** to verify; the
  new score appears as the latest scan in the history. The run's output is shown in the dialog and
  audited (`host.remediate`).
- Rules that touch SSH, the firewall, account lockout, networking sysctls (`ip_forward`,
  `rp_filter`, `route_localnet`, `send_redirects`, `ip_local_port_range`), or Fleet's privilege path
  (`sudo_*` such as `noexec`/`requiretty`, and direct/root-login lockout) are flagged **⚠
  access-impacting** because their fixes can sever Fleet's own access to or automation of the host —
  enrollment and remediation run non-interactive `sudo bash`, which `Defaults noexec`/`requiretty`
  breaks. Applying any of them requires an explicit extra confirmation. **Remediation changes host
  configuration and is not automatically reversible — test on non-critical hosts first.**
- Remediating a **control-plane host** — the jump host, a host tagged `control-plane`/`protected`, or
  one listed in `FLEET_CONTROL_PLANE_HOSTS` — requires a second, distinct confirmation. Hardening the
  box that runs Fleet (e.g. an `ip_forward=0` sysctl that breaks Docker's bridge networking) can lock
  Fleet out of the entire fleet; only proceed with out-of-band console access to recover. If it does
  get locked out, see the recovery runbook: [break-glass §5](break-glass.md#5-recovering-after-hardening-locked-fleet-out-of-its-own-host).
- The scan needs SCAP content matching the host's **OS version** (e.g. `ssg-debian13-ds.xml`
  for Debian 13). If a host's distro is newer than its packaged `scap-security-guide`, Fleet
  **auto-provisions** the right datastream: the backend downloads the ComplianceAsCode release
  **once** (cached under `FLEET_SCAP_CONTENT_DIR`) and pushes the matching `ssg-*-ds.xml` to the
  host over SSH during prepare/scan — so hosts never need internet access to GitHub. Pin a
  release with `FLEET_SCAP_CONTENT_VERSION` (default: latest); set `FLEET_SCAP_CONTENT_DIR=`
  empty to disable auto-provisioning. The scan row shows which `ssg-*-ds.xml` was used.
- Debian/Ubuntu have **no DISA STIG** profile; the closest hardening baseline is
  **ANSSI-BP-028 (High / Enforced)**.

## Vulnerability scans (CVE)

CVE scanning is separate from OpenSCAP compliance (above): it matches a host's
**installed packages** against a CVE database and scores findings by **CVSS**.
Nothing is installed on the host — the backend tars the package databases over SSH
and a **grype-scanner sidecar** does the matching.

1. Open the **Vulnerabilities** page (sidebar; needs `Host.Scan`).
2. **Scan a host** or **a whole group** — on demand here, or on a recurring basis
   with a `vulnscan` **schedule** (Schedules page). Progress streams live.
3. Read the **fleet roll-up**: per host, the **max CVSS** and counts of
   **critical / high / medium** findings. Sort to triage worst-first.
4. **Drill in** to a host for the findings table — CVE id, package, **installed vs.
   fixed** version, severity, CVSS score and vector, data source, and description.
   The *fixed* column tells you which package upgrade closes the finding.
5. Export evidence from **Reports → `vulnerabilities.csv`** (see Compliance reports).

Findings are **severity-gated notified** (route them under Notifications) and
audited. If a host shows no data, confirm the sidecar is up and the **CVE database
is loaded** (below).

## CVE database (online & offline)

The scanner needs a CVE database, persisted in the `grype-db` volume. Manage it from
the **Vulnerabilities** page (needs `System.Configure`); the current **build date**
is shown.

- **Online:** click **Update** to pull a fresh Grype DB — the backend/sidecar must
  have **internet access**.
- **Air-gapped:** on an internet-connected machine, download a **Grype DB archive**,
  copy it in, then **Import** it here. Grype's DB age-validation is disabled, so a
  self-managed DB of any age is accepted — but refresh it regularly so new CVEs are
  caught.

> Load or import the database **before** the first scan; a scan against an empty DB
> returns no findings rather than an error.

## Ansible playbooks

The **Playbooks** page (needs `Playbook.Edit`) is an authoring and run console for Ansible.
Write a YAML playbook in the editor, then:

- **Validate** — syntax-check (`ansible-playbook --syntax-check`).
- **Lint** — `ansible-lint` style/correctness checks.

Both run in the **ansible-runner sidecar** (a separate container, `FLEET_ANSIBLE_RUNNER_URL`);
if it's unreachable the dialog says so and Validate/Lint are unavailable. Every save keeps a
**version** history.

**Run** (needs `Playbook.Run`, admin-only by default) executes the playbook against one or more
**hosts** or a **group**. **Dry run (check mode)** is on by default — it reports what *would*
change without applying anything; clear it to apply for real. Output **streams live**
(auto-scrolling) and each playbook keeps its own **run history**.

Runs go through the jump host as the privileged **`fleet`** account over certificate auth (the
same path as scans) and execute under sudo, so your plays should target **`hosts: all`** — Fleet
supplies the inventory and limits it to the hosts/group you selected. The default new-playbook
template is already set up this way.

> **`Playbook.Run` is effectively arbitrary root-level change on the selected hosts.** Keep it
> admin-only, dry-run first, and test on non-critical hosts.

## Schedules

The **Schedules** page (needs `Schedule.Manage`) runs scans or playbook runs on a recurring
basis. Create a schedule (**interval**, **daily**, or **weekly**), pick its target, and it's
**disabled until you enable it**. Each row shows the **enable toggle**, **next run**, **last
run** (and status), and a **Run now** action. Results land in the normal scan / playbook **run
history**, tagged **scheduled** so you can tell automated runs from manual ones. Daily/weekly
clock times are interpreted in the configured **app time zone**.

## Time zone

**Settings → Time zone** sets the app-wide **IANA** zone (e.g. `America/Chicago`). It drives
**all displayed timestamps** and how schedule clock-times are interpreted — changing it
recomputes upcoming schedule runs.

## Notifications

**Settings → Notifications** (admin) routes events to **Email** (generic SMTP) and/or a
**Webhook** (raw **JSON**, **Slack**, **Discord**, or **Microsoft Teams**). For each channel,
choose which events go to it:

- **Host went offline / recovered**
- **Access request pending approval**
- **Access request approved or denied**
- **Just-in-time access expired**
- **Security scan found failures**
- **Failed playbook run**
- **Vulnerability (CVE) findings**
- **Scheduled compliance report** (`report.scheduled`) — deliver to **Email** for the CSV
- **Fleet-health digest** (`fleet.digest`)

Set a **throttle** (minutes) to dedupe repeats, and use **Send test** to confirm delivery.
Notifications are **off by default** — nothing is sent until you enable a channel.

**Page on-call (PagerDuty / Opsgenie).** Two **incident channels** page instead of posting per
event: **PagerDuty** (Events API v2 — a routing/integration key) and **Opsgenie** (Alerts API —
an API key, US or EU region); keys are stored encrypted. Rather than the per-event matrix, each
fires on **any** event at or above a **minimum severity** you set — *errors only*,
*warnings + errors*, or *everything* — which keeps info-level traffic (digests, scheduled
reports) from paging. Enable it, paste the key, pick the minimum severity (and region), and
**Send test**.

For the two lifecycle events — a request being **resolved** and a grant **expiring** —
routing the event to **Email** also emails the affected **requester directly** at the address
in their profile (in addition to the admin distribution list), falling back silently if they
have none. The Email route is the single gate: disabling it silences both the admin copy and
the requester's, so enable Email for these events if you want requesters to get closure.

There is also a **CA key due for rotation** event: the renewal loop checks the active
SSH CA key's age hourly and, once it passes `FLEET_CA_ROTATE_AFTER` (default 365 days),
raises this notification (throttled ~weekly). Rotate with `fleetctl rotate-ca` or from the
**Certificates** page.

## Compliance reports

The **Reports** page (needs `Audit.View`) exports **CSV** evidence over a date range you pick
(`from`/`to`; default last 30 days, `to` exclusive):

- **Access** — SSH sessions (user, host, client IP, start/end, status, bytes)
- **Audit** — audit events with full, untruncated detail
- **Certificates** — SSH cert issuance and revocation
- **Scans** — OpenSCAP posture over time
- **Vulnerabilities** — CVE findings (host, package, installed/fixed, severity, CVSS)

### Scheduling delivery

To have reports arrive automatically:

1. **Settings → Scheduled compliance reports**. Choose **weekly** or **monthly**, a **day** and
   **hour**, and the lookback window; save.
2. Under **Notifications**, route the **Scheduled compliance report** (`report.scheduled`) event
   to **Email** — reports are delivered as **CSV email attachments**, and the webhook channel
   drops attachments.
3. Use **Send now** to test delivery without waiting for the schedule.

## Fleet-health digest

Get a recurring summary of what needs attention across the fleet — offline hosts, low disk (with
a **days-to-full** projection), high memory/load, and pending security updates:

1. **Settings → Fleet-health digest**. Choose **daily** or **weekly** and save.
2. Route the **Fleet-health digest** (`fleet.digest`) event to a channel under **Notifications**.
3. **Preview** shows the current digest; **Send now** delivers one immediately.

The same signals power the Dashboard **"Needs attention"** card and the Ask AI assistant's
"what's wrong with the fleet?" answers.

## Audit forwarding (SIEM)

**Settings → Audit forwarding (SIEM)** (admin) forwards **every** audit event to an external
collector — **syslog** (RFC 5424, over **UDP** or **TCP**) or an **HTTP JSON** endpoint. Set
the **type**, the **address** (`host:port` for syslog, a URL for HTTP), and the **protocol**
(syslog only), then enable it. Use **Send test event** to confirm the collector receives it.
Forwarding is **best-effort and off by default** — the in-app **hash-chained audit log stays
the system of record**, so a dropped forward never blocks an action.

## System Health

The **Health** page (admin / `System.Configure`) shows the **live status** of the deployment
and **auto-refreshes**. It reports ok/warn/error for the **database**, the **certificate
authority** (including the **CA key's age**), **jump host** reachability, the **ansible-runner**
sidecar, **backups** (count + age of the latest), and **every background job** (monitor,
certificate renewal, the approval reaper, retention, and KRL distribution) with each job's last
run and any last error. Check it first when something looks wrong fleet-wide.

## Backup & Restore

**Settings → Backup & Restore** (admin) takes **encrypted database backups**: `pg_dump` piped
through `openssl` **AES-256**, written as `fleet-backup-<ts>.sql.enc`. **Back up now** runs one
immediately; an optional **schedule** (interval) plus **retention** (keep last N) automates it;
**Download** saves a backup file.

Restore is an **offline** operation — decrypt and load straight into Postgres, e.g.
`openssl enc -d -aes-256-cbc -pbkdf2 -in <file>.sql.enc | psql …`. The full, tested procedure is
the [Break-Glass & Recovery Runbook](./break-glass.md).

> Map **`FLEET_BACKUP_DIR`** (default `/var/lib/fleet/backups`) to **off-host** storage, and keep
> **`FLEET_BACKUP_PASSPHRASE`** **off the server** (password manager / sealed envelope). It is
> deliberately *not* in the backup, so a stolen backup can't be decrypted.

## Host support bundle

Click the **support bundle** (first-aid) icon on a host row to download a single
`.tar.gz` of diagnostics for troubleshooting. It needs `Host.Scan` **and** access
to the host (super admins bypass). The backend connects over the jump host as the
privileged `fleet` account and collects, into one archive:

- **Command outputs** — uname/OS, uptime + load, CPU, memory, `top`, disk usage
  (`df`, inodes, largest dirs), block devices/mounts, network (addresses, routes,
  listening sockets, link stats, DNS), top processes by CPU/memory, systemd
  failed/running units, pending package updates, recent logins, WireGuard, and
  firewall rules.
- **Logs** (tail-bounded to keep the bundle small) — `syslog`/`messages`,
  `auth.log`/`secure`, `kern.log`, the systemd journal (recent), and `dmesg`.

Generation runs over SSH and takes a few seconds; the file downloads when ready.
Nothing is stored on the server. Note the bundle includes auth/system logs, so
treat it as sensitive.

## Just-in-time access

Users without permanent group access request temporary access under **Approvals → My requests**.
Pick **Host** or **Group**, then choose one or more targets from a **searchable name picker**
that queries the fleet as you type (targets you can already reach are omitted) — selecting
several files a request for each.
Add a reason, duration, and optional ticket. Approvers act under **Approvals → Queue**, where
each request shows the requester, the target, and — once resolved — **who approved or denied it**,
when, and any decision note. Grants expire automatically; a background reaper revokes elapsed
grants every minute.

When an approver resolves a request, Fleet notifies the configured admin channel **and** emails
the requester directly (if they have a profile email); when a grant later expires, the requester
is emailed again. See [Notifications](#notifications) to enable delivery.

## Audit integrity

**Audit → Verify integrity** recomputes the hash chain; any tampering with a historical row
makes verification fail and reports the first broken sequence number.

## Certificate revocation (enforced on hosts)

Revocation is enforced end-to-end via OpenSSH KRLs:

- Enrollment installs `/etc/ssh/fleet_krl` and adds `RevokedKeys /etc/ssh/fleet_krl` to the
  host's sshd config (rolled back automatically if sshd would reject it — hosts are never
  locked out).
- Logout, idle/absolute timeout, and account disable/delete revoke the session's certificate
  into the KRL (`cert_revocations`); an admin can also revoke a specific serial from the
  **Certificates** page.
- The backend rebuilds the KRL (`ssh-keygen -k`) and **pushes it to all enrolled hosts**:
  immediately after a manual revoke, and within ~10 minutes for other revocations (background
  `krl-distribution` job). `POST /api/v1/certificates/krl/distribute` forces an immediate push.
- Hosts read `RevokedKeys` on every authentication, so updates take effect with no sshd reload.
- KRL entries for already-expired certificates are pruned automatically so the list stays small.
