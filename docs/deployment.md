# Fleet Terminal — Deployment Guide

How to stand up the **entire system**: the application stack (backend, frontend,
PostgreSQL, Redis), the SSH egress path (jump host + WireGuard), and the
production hardening. For putting the UI on the public internet behind a reverse
proxy, see [internet-exposure.md](./internet-exposure.md).

---

## 1. Architecture recap

```
Operators ──HTTPS/WSS──> Reverse proxy ──> frontend (nginx) ──/api──> backend (Go)
                                                                         │ sole SSH client
                                                              ┌──────────┴───────────┐
                                                              │ Postgres   Redis      │
                                                              └──────────┬───────────┘
                                                                         │ SSH (ephemeral cert)
                                                                  Jump host (WireGuard server)
                                                                         │ WireGuard overlay
                                                                  Managed Linux hosts
```

- The **browser never speaks SSH** and never holds a key. The backend is the only
  SSH client; it dials each host through the jump host over WireGuard using a
  short-lived, per-(user,host) certificate.
- The compose stack also starts an **`ansible-runner` sidecar** — an internal-only
  container (not published on the host) that validates/lints and runs Ansible
  playbooks so the lean Go backend never needs a Python toolchain. The backend
  reaches it at `FLEET_ANSIBLE_RUNNER_URL` (default `http://ansible-runner:8000`).
- **You provide:** a host for the app stack (Docker), a **jump host** reachable
  from your managed hosts on a UDP WireGuard port, and the managed hosts
  themselves. The bundled test fabric provides all of this locally for evaluation.

---

## 2. Prerequisites

- Docker + Docker Compose (the only hard requirement for the app stack — no local
  Go/Node/Postgres toolchain needed).
- A **jump host** running WireGuard + OpenSSH that the backend can SSH to and that
  your managed hosts can reach on UDP (default 51820). You can **co-locate it as a
  container** on the same Docker server (single-server deployment, §5a) or run it
  on a separate box (§5b).
- TLS termination for production (a reverse proxy such as Nginx Proxy Manager,
  Caddy, or an ingress controller) with a certificate (e.g. Let's Encrypt).

---

## 3. Configuration (environment)

All configuration is environment variables, so the same image runs everywhere.
Start from a template:

```sh
cp .env.example .env                 # local / evaluation
cp .env.production.example .env      # production starting point
```

Keep `.env` at the **repo root** and always use the `make` targets (or pass
`--env-file .env` to `docker compose` yourself). Compose otherwise loads `.env`
from the compose file's directory (`deploy/compose/`), silently ignoring your
settings and falling back to defaults.

Generate strong secrets (required in production):

```sh
openssl rand -hex 32   # FLEET_JWT_SECRET
openssl rand -hex 32   # FLEET_CSRF_SECRET
openssl rand -hex 32   # FLEET_CA_PASSPHRASE   (encrypts the SSH CA key at rest)
```

Key variables (full list in `.env.example`):

| Variable | Purpose |
|---|---|
| `FLEET_ENV` | `development` or `production` |
| `FLEET_PUBLIC_URL` | Public HTTPS URL; drives CORS, cookies, WebAuthn |
| `FLEET_JWT_SECRET` / `FLEET_CSRF_SECRET` | Token + CSRF signing (≥16 bytes) |
| `FLEET_CA_PASSPHRASE` | Encrypts the internal SSH CA private key at rest |
| `POSTGRES_PASSWORD` | Database password |
| `FLEET_COOKIE_SECURE` | `true` whenever served over HTTPS |
| `FLEET_SESSION_IDLE_TTL` / `_ABSOLUTE_TTL` | Session inactivity / hard-cap lifetimes |
| `FLEET_REFRESH_TOKEN_TTL` | Refresh-cookie lifetime (shorten for internet exposure) |
| `FLEET_USER_CERT_TTL` | Ephemeral user-cert lifetime (default 7d, auto-renewed) |
| `FLEET_RATE_LIMIT_*` / `FLEET_AUTH_RATE_LIMIT_*` | Per-IP rate limits (0 disables) |
| `FLEET_JUMP_HOST` / `FLEET_JUMP_USER` | Jump host `host:port` + login user |
| `FLEET_WG_SUBNET` / `FLEET_WG_JUMP_IP` / `FLEET_WG_PORT` | WireGuard overlay |
| `FLEET_WG_JUMP_ENDPOINT` | Public `host:port` managed hosts dial to reach the jump |
| `FLEET_ALLOW_BOOTSTRAP` | `false` after the first admin exists (also self-seals) |
| `FLEET_BACKUP_DIR` | Where encrypted DB backups are written (default `/var/lib/fleet/backups`, the `backups` volume) |
| `FLEET_BACKUP_PASSPHRASE` | Encrypts DB backups (`openssl` AES-256); falls back to `FLEET_CA_PASSPHRASE` if empty — keep it **off-host** |
| `FLEET_ANSIBLE_RUNNER_URL` | Base URL of the `ansible-runner` sidecar (default `http://ansible-runner:8000`) |
| `TZ` | *(optional)* server timezone for the backend; schedules compute next-run in this zone (default `UTC`) |

> **Backups** are produced under **Settings → Backup & Restore** (encrypted,
> schedulable, with retention) and written to `FLEET_BACKUP_DIR`. See
> [break-glass.md](./break-glass.md) and [disaster-recovery.md](./disaster-recovery.md).
> The `TZ` env sets the server timezone, but the **in-app Time zone setting is
> preferred** for schedule display/computation.
>
> **Notifications** (SMTP email + webhooks) are configured **in the UI**
> (Settings → Notifications) — no environment variables needed; the SMTP password
> is encrypted at rest.

---

## 4. Local / evaluation stack

The fastest way to see the whole system working end-to-end:

```sh
make up        # Postgres, Redis, backend, frontend + SSH test fabric (jump + 2 hosts)
make trust     # seed the test-fabric hosts with the backend's CA (run once per `make up`)
```

Open <http://localhost:5173>, complete the **bootstrap wizard** to create the
first Super Administrator, then enroll a fabric host and connect a terminal. See
[operations.md](./operations.md). `make down` stops; `make clean` removes volumes
(destroys data).

---

## 5. Production stack (Docker Compose)

Common to both layouts:

1. **Configure** `.env` from `.env.production.example`: real secrets, your
   `FLEET_PUBLIC_URL`, `FLEET_COOKIE_SECURE=true`, `FLEET_ALLOW_BOOTSTRAP=false`
   (after first run), and `FLEET_WG_JUMP_ENDPOINT` set to the jump host's
   **publicly routable** `host:port` (not an internal name) — this is what your
   managed hosts dial over UDP.
2. **Persist data.** PostgreSQL data, recordings, and encrypted backups live in
   named volumes (`pgdata`, `recordings`, `backups`); back them up and store the
   backup files off-host (see [disaster-recovery.md](./disaster-recovery.md) and
   [break-glass.md](./break-glass.md)). Point the DB at a managed Postgres in
   production by overriding `FLEET_DATABASE_URL`.
3. **Front it with TLS.** Put a reverse proxy in front, terminate HTTPS, and
   forward to the `frontend` container (which proxies `/api` to the backend).
   Only the proxy should be internet-reachable. Reverse-proxy, rate-limit, and
   WAF guidance is in [internet-exposure.md](./internet-exposure.md).
4. **Bootstrap.** Browse to the URL, create the Super Administrator, then set
   `FLEET_ALLOW_BOOTSTRAP=false` and restart the backend.

### 5a. Single server (co-located jump host)

Run **everything on one Docker host** — database, cache, backend, frontend, and
the WireGuard jump host:

```sh
make up-single   # app stack + deploy/compose/docker-compose.jumphost.yml
```

The bundled jump host:

- **publishes** the WireGuard UDP port (`FLEET_WG_PORT`, default 51820) so remote
  managed hosts can reach it — **open that UDP port on the host firewall**;
- **auto-trusts the Fleet CA** by polling the backend's public CA endpoint
  (`GET /api/v1/certificates/ca/pub`) — no manual trust step, and it tracks CA
  rotation automatically;
- **persists** its WireGuard keypair + peers (`jump_wg`) and SSH host key
  (`jump_ssh`) on volumes, so restarts/upgrades don't break enrolled hosts or
  `known_hosts` pinning.

Set `FLEET_WG_JUMP_ENDPOINT=<server-public-host>:51820` in `.env` so enrolled
hosts dial the right address. The backend reaches the jump host internally at its
default `jumphost:22`.

> Co-locating is ideal for small/single-server deployments. For larger or
> higher-security setups, keep the jump host on a separate minimal box (§5b) so
> public WireGuard ingress isn't on the control-plane server.

To manage the Fleet server itself as a host, enroll it with the **Directly
reachable / skip WireGuard** option: a host co-located with the jump host can't run
a second WireGuard endpoint on the jump's port, so enrollment skips the overlay and
the gateway reaches it at its management address through the jump host (see the
[Host Enrollment Guide](./host-enrollment-guide.md)).

### 5b. External jump host (separate box)

Run only the app stack and point it at a jump host you operate elsewhere:

```sh
make up-app      # or: docker compose --env-file .env -f deploy/compose/docker-compose.yml up -d
```

Set `FLEET_JUMP_HOST` / `FLEET_JUMP_USER` to your jump host, ensure it trusts the
Fleet CA (`GET /api/v1/certificates/ca/pub`) and runs WireGuard on
`FLEET_WG_JUMP_ENDPOINT`. See §6.

### Other deployment targets

`deploy/` also contains Kubernetes manifests (`deploy/k8s`), a Helm chart
(`deploy/helm`), and systemd units (`deploy/systemd`) for non-Compose
environments. They consume the same environment variables described above.

---

## 6. The jump host & WireGuard

The jump host is the single egress point. It must:

- run OpenSSH and **trust the Fleet CA** (so the backend can SSH in with its
  system certificate) — `FLEET_JUMP_USER` maps to the `fleet` principal;
- run WireGuard as the overlay server on `FLEET_WG_PORT`, with its public key
  readable at `/etc/wireguard/publickey`;
- be reachable from managed hosts at `FLEET_WG_JUMP_ENDPOINT` (UDP).

Enrollment adds each managed host as a WireGuard **peer** on the jump host
automatically. The container uses userspace `wireguard-go`, so it needs no kernel
module — it runs on any Linux Docker host with `NET_ADMIN` + `/dev/net/tun`
(already set in the overlay).

The **co-located** jump host (§5a) satisfies all three requirements automatically:
it self-trusts the CA on boot, generates and persists its WireGuard keypair, and
re-applies persisted peers on restart. For an **external** jump host you establish
CA trust once (install `GET /api/v1/certificates/ca/pub` as `TrustedUserCAKeys`,
principal `fleet`) and run WireGuard yourself.

---

## 7. Post-deploy hardening checklist

- [ ] `FLEET_ENV=production`, `FLEET_COOKIE_SECURE=true`, HTTPS + HSTS at the proxy.
- [ ] Strong `FLEET_JWT_SECRET`, `FLEET_CSRF_SECRET`, `FLEET_CA_PASSPHRASE`.
- [ ] `FLEET_ALLOW_BOOTSTRAP=false` once the first admin exists.
- [ ] **Require MFA** for all users (Users → *Require MFA for all*) or per user.
- [ ] Per-IP rate limits set; `lockout_policy` tuned (Settings/Security).
- [ ] Only the reverse proxy is internet-reachable; DB/Redis/jump/WireGuard stay
      internal.
- [ ] `FLEET_JUMP_KNOWN_HOSTS` set so the gateway pins the jump host key.
- [ ] **Encrypted, scheduled backups** enabled (Settings → Backup & Restore) with
      retention, written to `FLEET_BACKUP_DIR` and copied **off-host**; recordings
      backed up; `FLEET_BACKUP_PASSPHRASE` (and `FLEET_CA_PASSPHRASE`) stored
      off-server. Restore-tested — see [break-glass.md](./break-glass.md).

---

## 8. Upgrades

- Pull/rebuild images and `docker compose up -d`. **Database migrations apply
  automatically on backend start** (`FLEET_MIGRATE_ON_START=true`), in order, and
  are logged (`migrations applied … versions=[…]`).
- Recordings and certificates survive restarts; ephemeral in-RAM keys are
  re-issued on the next authenticated request.

---

## 9. Recovery & operations

- Out-of-band admin recovery (locked out, reset MFA, rotate CA) uses the
  `fleetctl` CLI baked into the backend image — see
  [disaster-recovery.md](./disaster-recovery.md).
- Day-to-day flows (enroll, connect, transfer, approvals, MFA) are in
  [operations.md](./operations.md); end-user usage in [user-guide.md](./user-guide.md).
