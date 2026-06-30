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
