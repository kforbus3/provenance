# Fleet Terminal — Local SSH Test Fabric

This directory contains a self-contained, browser-demonstrable SSH fabric for
Fleet Terminal. It lets you exercise the full connect path on a laptop —
including **macOS + Docker Desktop**, which has **no WireGuard kernel module**.
Each node prefers the **kernel** WireGuard module and falls back to userspace
[`wireguard-go`](https://git.zx2c4.com/wireguard-go) over `/dev/net/tun` when the
module is unavailable, so the fabric runs on a Mac (userspace) or a Linux host
with the module loaded (kernel) without changes.

## Topology

```
  ┌──────────┐    ssh :22     ┌──────────┐   wg0 (10.100.0.0/24)   ┌──────────────┐
  │ backend  │ ─────────────▶ │ jumphost │ ───────────────────────▶│ host-ubuntu  │ 10.100.0.21
  │ (Go)     │   ProxyJump    │  (hub)   │        userspace        │ host-rocky   │ 10.100.0.22
  └──────────┘                └──────────┘        WireGuard        └──────────────┘
       fleet docker bridge (172.30.0.0/16)
```

- **backend** opens an SSH connection to `jumphost:22` (`FLEET_JUMP_HOST` /
  `FLEET_JUMP_USER` in the main compose file) and uses the jump host as an SSH
  `ProxyJump` to reach the managed hosts over the WireGuard overlay.
- **jumphost** is the WireGuard **hub**. It listens on UDP `51820` and peers
  with every managed host.
- **host-ubuntu** / **host-rocky** are WireGuard **spokes**. Each peers only
  with the hub and is reachable from the jump host at its `10.100.0.x` overlay
  address.

| Node          | Docker IP (fleet) | WireGuard IP (wg0) | Base image      |
| ------------- | ----------------- | ------------------ | --------------- |
| jumphost      | 172.30.0.10       | 10.100.0.1         | ubuntu:22.04    |
| host-ubuntu   | 172.30.0.21       | 10.100.0.21        | ubuntu:22.04    |
| host-rocky    | 172.30.0.22       | 10.100.0.22        | rockylinux:9    |

## Kernel-first, userspace fallback

The jump host and managed hosts both try to create a **kernel** WireGuard
interface first (`ip link add … type wireguard` / `wg-quick`), which requires the
`wireguard` module to be loaded on the Docker **host** — on a Linux host, run
`modprobe wireguard` (or let the distro autoload it). When the module is not
available — as inside the Docker Desktop LinuxKit VM on macOS — they fall back to
`wireguard-go`, the official userspace implementation. It creates a normal `tun`
interface (`wg0`) through `/dev/net/tun`, so it works anywhere the container has
the `NET_ADMIN` capability and the tun device. Both are granted in
`docker-compose.testfabric.yml`:

```yaml
cap_add:    [NET_ADMIN]
devices:    [/dev/net/tun:/dev/net/tun]
```

`wireguard-go` is built from source in a small `golang:1.23-alpine` build stage
and copied into each image, so the fabric does not depend on distro WireGuard
packaging (which differs between Ubuntu and Rocky).

## Key generation & peer config

There are no hard-coded keys. On first boot each node:

1. Generates a persistent keypair with `wg genkey` / `wg pubkey`
   (stored in `/etc/wireguard/privatekey` and `/etc/wireguard/publickey`).
2. Publishes its **public** key to the shared `wgkeys` Docker volume mounted at
   `/wgkeys`, as `/wgkeys/<node-name>.pub`.
3. Brings up `wg0` with `wireguard-go`, sets its listen port and private key,
   and assigns its overlay address.
4. Discovers peers by polling `/wgkeys` for the other nodes' `.pub` files, then
   configures each peer with `wg set`:

   - **Hub (jumphost)** adds every spoke:
     ```sh
     wg set wg0 peer <spoke-pubkey> \
       allowed-ips 10.100.0.21/32 \
       endpoint host-ubuntu:51820 \
       persistent-keepalive 25
     ```
   - **Spoke (managed host)** adds the hub:
     ```sh
     wg set wg0 peer <hub-pubkey> \
       allowed-ips 10.100.0.1/32 \
       endpoint jumphost:51820 \
       persistent-keepalive 25
     ```

   Endpoints use Docker DNS names on the `fleet` network, so addressing is
   stable across restarts. The peer list for the hub is driven by the
   `WG_PEERS` env var (defaults to `host-ubuntu:10.100.0.21 host-rocky:10.100.0.22`);
   each spoke is parameterized by `WG_NAME`, `WG_ADDRESS`, `JUMP_NAME`, and
   `JUMP_WG_IP`.

## SSH / certificate trust

Each node runs `sshd` configured (via `/etc/ssh/sshd_config.d/00-fleet.conf`)
to trust the **fleet user CA**:

```
PasswordAuthentication no
PubkeyAuthentication   yes
TrustedUserCAKeys      /etc/ssh/fleet_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

- `/etc/ssh/fleet_ca.pub` ships as a **placeholder**. The Fleet Terminal
  enrollment flow overwrites it with the real CA public key so that
  certificates minted by the platform are accepted.
- `/etc/ssh/auth_principals/fleet` contains the single principal `fleet`, so a
  certificate carrying the `fleet` principal may log in as the `fleet` user.
- The login user `fleet` exists on every node; on the managed hosts it also has
  **passwordless sudo** (`/etc/sudoers.d/fleet`).

## Running

From the repo root:

```sh
docker compose \
  -f deploy/compose/docker-compose.yml \
  -f deploy/compose/docker-compose.testfabric.yml \
  up -d
```

This starts Postgres, Redis, the backend, the frontend, the jump host, and both
managed hosts on the shared `fleet` bridge network.

### Smoke test the overlay

```sh
# Confirm the hub sees both spokes handshaking.
docker compose -f deploy/compose/docker-compose.yml \
               -f deploy/compose/docker-compose.testfabric.yml \
               exec jumphost wg show

# From the hub, ping a managed host across the WireGuard overlay.
docker compose -f deploy/compose/docker-compose.yml \
               -f deploy/compose/docker-compose.testfabric.yml \
               exec jumphost ping -c2 10.100.0.21
```

After enrollment has replaced `/etc/ssh/fleet_ca.pub` with the real CA key, the
backend can connect: `backend → jumphost:22 → ProxyJump → 10.100.0.21 (fleet@host-ubuntu)`.
