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

## AI assistant (Ask Fleet)

An optional, **local-only** assistant answers natural-language questions about the fleet —
"which hosts have less than 20% disk free?", "offline debian hosts", "prod hosts under heavy
load". It's **read-only**: a local Ollama model translates the question into a curated
`query_hosts` filter, the backend runs that query (scoped to hosts *you* can access) and shows
the **actual matching hosts** beside the answer — no data leaves your network, and every
question is audited.

**Enable it (admin):** **Settings → AI assistant** — turn it on, enter your Ollama URL
(e.g. `http://10.10.0.x:11434`), click **Load models**, pick a model, **Save**. Then users with
the `Assistant.Use` permission get an **Ask** item in the sidebar. The assistant never runs
commands or changes anything; treat answers as a starting point and verify before acting.

## Two-factor authentication (TOTP / passkeys)

1. **Security → Set up authenticator**. **Scan the QR code** (generated in the browser, so the
   secret never leaves the machine) or enter the secret key manually, then enter the current
   6-digit code to confirm. Passkeys (WebAuthn) can be registered from the same page.
2. Subsequent sign-ins prompt for the code after the password step.
3. Remove a factor from the same page. (Admins can reset a locked-out user's factors.)

**Requiring MFA.** MFA is optional by default. Admins can enforce it globally
(**Users → Require MFA for all**) or per user (Users → Edit → *Require MFA*). When required and
a user has no factor, their next sign-in walks them through enrollment before any session is
issued — no separate setup step needed.

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
- Rules that touch SSH, the firewall, or account lockout are flagged **⚠ access-impacting** because
  their fixes can sever Fleet's own access to the host; applying any of them requires an explicit
  extra confirmation. **Remediation changes host configuration and is not automatically reversible —
  test on non-critical hosts first.**
- The scan needs SCAP content matching the host's **OS version** (e.g. `ssg-debian13-ds.xml`
  for Debian 13). If a host's distro is newer than its packaged `scap-security-guide`, Fleet
  **auto-provisions** the right datastream: the backend downloads the ComplianceAsCode release
  **once** (cached under `FLEET_SCAP_CONTENT_DIR`) and pushes the matching `ssg-*-ds.xml` to the
  host over SSH during prepare/scan — so hosts never need internet access to GitHub. Pin a
  release with `FLEET_SCAP_CONTENT_VERSION` (default: latest); set `FLEET_SCAP_CONTENT_DIR=`
  empty to disable auto-provisioning. The scan row shows which `ssg-*-ds.xml` was used.
- Debian/Ubuntu have **no DISA STIG** profile; the closest hardening baseline is
  **ANSSI-BP-028 (High / Enforced)**.

## Just-in-time access

Users without permanent group access request temporary access under **Approvals → My requests**.
Pick **Host** or **Group**, then choose one or more targets from a **searchable name picker**
that queries the fleet as you type (targets you can already reach are omitted) — selecting
several files a request for each.
Add a reason, duration, and optional ticket. Approvers act under **Approvals → Queue**. Grants
expire automatically; a background reaper revokes elapsed grants every minute.

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
