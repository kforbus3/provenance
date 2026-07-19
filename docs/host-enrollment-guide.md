# Fleet Terminal — Host Enrollment Guide

Enrollment makes a managed host reachable through Fleet Terminal. The goal is for
the host to **trust the Fleet user CA** so that any short-lived user certificate
the platform issues is accepted — without distributing per-user keys or managing
`authorized_keys`.

## Concepts

- **User CA.** Fleet runs an SSH certificate authority (`ssh-ed25519`). Its public
  key is configured as a `TrustedUserCAKeys` on every managed host. Its private
  key is encrypted at rest (`FLEET_CA_PASSPHRASE`) and never leaves the backend.
- **Reachability.** Managed hosts are not exposed directly. The backend reaches
  them through the **jump host** (`FLEET_JUMP_HOST`) over a **WireGuard** tunnel
  network. Each host record carries both a routable `address` and a `wg_address`.
- **Host record.** A row in the `hosts` table holds hostname, environment, owner,
  addresses, SSH port/user, tags, and an `enrolled` flag. Collected facts land in
  `host_inventory`; known host keys in `host_fingerprints`; live status in
  `host_status`. Enrollment runs are tracked in `enrollment_jobs`.

## Prerequisites

- The host runs OpenSSH and is reachable from the jump host over the WireGuard
  network.
- You hold the **Host.Enroll** permission.
- The Fleet user CA exists (created automatically on first backend start;
  retrievable via `GET /api/v1/certificates/ca` → `activeUserCA`).

## Step 1 — Add the host to inventory

`POST /api/v1/hosts` (requires `Host.Enroll`):

```json
{
  "hostname": "web-01",
  "description": "frontend node",
  "environment": "production",
  "owner": "platform-team",
  "address": "10.0.1.5",
  "wgAddress": "10.9.0.5",
  "sshPort": 22,
  "sshUser": "fleet",
  "tags": ["web", "edge"]
}
```

The response includes the new host `id`. This writes a `host.create` audit event.

## Step 2 — Bootstrap the host (install CA trust + WireGuard)

Click the **Enroll** (cable) icon on the host row and pick how Fleet should reach
the host for the one-time bootstrap. All methods install the CA trust + login
user + sshd config and bring up WireGuard; they differ only in how the bootstrap
SSH connection authenticates:

| Method | Use when | Laptop install | Where the secret lives |
|---|---|---|---|
| **SSH password** | host has no prior setup and allows password auth | none | password, sent once over HTTPS |
| **SSH private key** | password auth is disabled; you have an authorized key | none | key pasted once over HTTPS |
| **SSH agent** | you want the key to never leave your machine | a small bridge binary | stays in your local agent (only signatures forwarded) |
| **No install (ssh-pipe)** | you want neither an install nor to upload a key | none | stays on your machine (your own `ssh`) |
| **Trusted (re-provision)** | host already trusts the Fleet CA | none | session certificate |

Any method can additionally set **Directly reachable / skip WireGuard** for a host
that needs no overlay:

| Option | Use when | Effect |
|---|---|---|
| **Directly reachable / skip WireGuard** | the host is on the **jump host's LAN**, or is **the host that runs Fleet itself** | the enroll request carries a `skipWireGuard` flag; enrollment installs CA trust + login accounts but **skips the WireGuard overlay** — no overlay address, no host WireGuard interface, no jump peer, and no tunnel verification. The gateway reaches the host at its **management `address`** through the jump host. |

**Why this exists.** A host co-located with the jump host (the single-server
deployment, where the jump host runs as a container on the same Docker server as
Fleet) can't stand up a second WireGuard endpoint on the jump's UDP port. Skipping
the overlay lets such a host enroll and be reached directly. When you select it,
the management **Address must be reachable from the jump host** (the WireGuard
endpoint field is disabled).

**SSH agent** runs `fleet-enroll-agent` (build with `make enroll-agent-all`,
distribute the per-OS binary). With your key loaded (`ssh-add`):

```sh
fleet-enroll-agent -url https://fleet.example.com -host web-01 \
  -token "$FLEET_TOKEN" -bootstrap-user opsadmin [-via-jump]
```

**No install (ssh-pipe)** generates a command you run in your own terminal; it
pipes a bootstrap script through *your* ssh and prints a host public key you paste
back into the Finish step:

```sh
curl -fsSL -H "Authorization: Bearer $TOKEN" \
  "https://fleet.example.com/api/v1/hosts/<id>/enroll/script" | ssh opsadmin@web-01 sudo bash
```

Each method streams its step log and shows the assigned overlay address.
Enrollment installs `/etc/ssh/fleet_ca.pub`, `TrustedUserCAKeys`, the
`AuthorizedPrincipalsFile` mapping, and **two login accounts** — the privileged
`fleet` account (principal `fleet`, NOPASSWD sudo) and a login-only
`fleet-login` account (principal `fleet-login`, no sudo); the requester's
`Host.Sudo` permission selects which one their certificate maps to. So you never
add per-user keys to `authorized_keys`. For the fully manual path,
fetch the CA with `GET /api/v1/certificates/ca`, configure `sshd_config`
yourself, then enroll with the **Trusted** method.

## Step 3 — Authorize users (groups or direct grants)

A user can reach a host through any of:

- **Shared group** — add the host and the user to the same group (host's
  **Manage access** dialog or `POST /api/v1/hosts/{hostId}/groups/{groupId}`;
  user: `POST /api/v1/users/{userId}/groups/{groupId}`).
- **Direct grant** — give an individual user access to a single host (host's
  **Manage access** dialog → *Individual users*, or
  `POST /api/v1/hosts/{hostId}/users/{userId}`).
- **Just-in-time** — a time-boxed approval grant (see the [User Guide](./user-guide.md)).

To review access at a glance: a host's **Manage access** dialog lists its groups
and directly-granted users; a user's **View accessible hosts** action lists every
host they can currently reach. Each connection issues a **unique certificate for
that (user, host) pair**.

## Step 4 — Verify connectivity

Have an authorized user open a terminal from the **Hosts** page (or, for a smoke
test, confirm the host shows **online** in `GET /api/v1/hosts/stats/status`).
A successful connection means:

- WireGuard tunnel up (`host_status.wg_ok`),
- SSH reachable through the jump host (`host_status.ssh_ok`),
- the host accepted a Fleet-issued user certificate.

## Windows (RDP) hosts

Windows hosts are enrolled onto the same WireGuard overlay as Linux hosts, but
they run no SSH — Fleet brokers **RDP** for sessions and uses **WinRM** to collect
facts. Enrollment is driven from the host's **Enroll** action, which produces a
**PowerShell** script you run **once, in an elevated (Administrator) PowerShell**
on the Windows host. That script is the only thing you run by hand; it configures
everything below automatically.

### What the enrollment script does

1. Installs **WireGuard for Windows** (via `winget`) if it isn't already present.
2. Generates a WireGuard keypair and writes a tunnel config with a fixed
   `ListenPort` (the configured `FLEET_WG_PORT`, default **51820**), so the jump
   host can reach the host inbound over the overlay exactly as it does a Linux
   host. Installs it as a persistent tunnel service (auto-connects on boot).
3. **Enables Remote Desktop** and opens its Windows Firewall group (TCP **3389**).
4. **Enables WinRM over HTTPS**: runs `Enable-PSRemoting`, creates a self-signed
   certificate, binds an HTTPS listener on TCP **5986**, and opens a firewall rule
   for it. Fact collection uses this (TLS), so no `AllowUnencrypted` is required.
5. Prints the host's WireGuard **public key** — paste it back into Fleet's
   **Finish enrollment** step to add the host as a peer on the jump host.

If step 1, 3, or 4 fails (e.g. `winget` unavailable on a stripped Server Core
install), the script prints a `WARN` and continues — the tunnel still comes up;
you can configure the missing piece by hand (see below).

### Ports and firewall

All of this traffic reaches the host **over the WireGuard interface** from the
jump host — nothing needs to be exposed to the LAN or internet directly.

| Port | Proto | Purpose | Opened by |
|---|---|---|---|
| 51820 (`FLEET_WG_PORT`) | UDP | WireGuard overlay | WireGuard for Windows |
| 3389 | TCP | RDP session | script (`Remote Desktop` firewall group) |
| 5986 | TCP | WinRM HTTPS (host facts) | script (`Fleet WinRM HTTPS` rule) |

If the Windows Firewall is on and you enroll manually, allow inbound **3389** and
**5986** (and, on a strict host, inbound UDP **51820**). Note that a freshly added
WireGuard adapter often lands in the **Public** firewall profile, while the RDP and
WinRM rules the script adds use `-Profile Any` so they still apply.

### The WireGuard endpoint (LAN vs. remote)

The endpoint baked into the host's tunnel config is your jump host's public
WireGuard endpoint by default. A host that shares the jump host's **LAN** still
works with the public endpoint — the jump reaches it *inbound* over the LAN (the
fixed `ListenPort` above), so the host never has to dial its own public address
(which a LAN host can't hairpin to). A **remote** host dials the public endpoint
outbound; ensure UDP `FLEET_WG_PORT` is forwarded to the jump host, exactly as a
remote Linux host requires.

### Manual WinRM setup (only if the script's step 4 was skipped)

Run in an elevated PowerShell on the host:

```powershell
Enable-PSRemoting -Force -SkipNetworkProfileCheck
$c = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $c.Thumbprint -Force
New-NetFirewallRule -DisplayName "Fleet WinRM HTTPS" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow -Profile Any
```

Fact collection authenticates over WinRM with the host's **vaulted credential**,
which must be a local administrator and have its access policy set to **open**
(the monitor never uses check-out-gated credentials). On a workgroup machine,
store the username as `Administrator` (the built-in account is exempt from the
remote UAC token filtering that restricts other local admins).

## Host key fingerprints

On first contact the host's SSH host key fingerprint is recorded in
`host_fingerprints` (`SHA256:…`) and pinned for subsequent connections, guarding
against man-in-the-middle changes. If a host is rebuilt and its key legitimately
changes, an administrator must clear/refresh the stored fingerprint.

## Rollback & troubleshooting

- Enrollment jobs record an ordered **step log** and status in `enrollment_jobs`
  (`pending → running → succeeded | failed | rolled_back`). A failed run is rolled
  back so the inventory isn't left half-configured.
- **Can't connect / "not authorized for host":** verify the user shares a group
  with the host (or has an active grant) and holds `Host.Connect`.
- **SSH refuses the certificate:** confirm `TrustedUserCAKeys` points at the
  current CA public key. If the CA was **rotated**, re-distribute the new public
  key (see [certificate-lifecycle.md](./certificate-lifecycle.md)).
- **Host shows offline:** check the WireGuard tunnel and that the jump host can
  reach `wg_address:ssh_port`.

## Decommissioning a host

`DELETE /api/v1/hosts/{id}` (requires `Host.Delete`) removes the host and, via
`ON DELETE CASCADE`, its group links, inventory, fingerprints, and status. The
deletion is audited. Optionally remove the `TrustedUserCAKeys` line on the host
if it is leaving the fleet entirely.
