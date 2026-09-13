# Installation Guide

This guide takes you from nothing to a running Provenance you can sign in to.
It covers the common **single-server** deployment (the application stack plus a
co-located jump host, all via Docker Compose). For production topologies, Kubernetes/
Helm, an external jump host, and the full hardening checklist, see the
[Deployment Guide](./deployment.md); to put the UI on the public internet, see
[Internet Exposure](./internet-exposure.md).

- **Audience:** whoever is standing the system up for the first time.
- **Result:** a running stack, a first administrator account, and a verified sign-in.
- **Time:** ~15 minutes on a prepared host.

---

## 1. Prerequisites

| Requirement | Notes |
|---|---|
| A Linux host | 2 vCPU / 4 GB RAM is comfortable to start; more for large fleets. |
| Docker + Docker Compose v2 | `docker --version` and `docker compose version` should both work. |
| `git` and `make` | Used to fetch the source and drive the stack. |
| Outbound network | For pulling images and (optionally) the CVE database. Air-gapped installs are supported — see §7. |

Optional, enabled later:

- **A domain name + TLS** for production (terminate TLS at a reverse proxy — see the Deployment and Internet-Exposure guides).
- **A local Ollama instance** if you want the "Ask Provenance" AI assistant (configured in the UI, not required to run).

> Provenance is the SSH control plane for your fleet. Install it on a host you
> trust and can lock down — it holds the SSH certificate authority.

---

## 2. Get the code

```bash
git clone https://github.com/kforbus3/provenance.git
cd provenance
```

---

## 3. Configure

Copy the example environment file and edit it:

```bash
cp .env.example .env
```

At minimum, set strong secrets. Generate each with `openssl rand`:

```bash
# 32+ byte random secrets
openssl rand -hex 32   # use for PROV_JWT_SECRET
openssl rand -hex 32   # use for PROV_CSRF_SECRET
openssl rand -hex 32   # use for PROV_CA_PASSPHRASE   (encrypts the CA private key)
openssl rand -hex 32   # use for POSTGRES_PASSWORD
openssl rand -hex 32   # use for PROV_BACKUP_PASSPHRASE (must differ from the CA passphrase)
```

Key settings in `.env`:

| Setting | Set it to |
|---|---|
| `PROV_ENV` | `production` (enables fail-closed validation of the secrets below) |
| `PROV_PUBLIC_URL` | The URL users will reach, e.g. `https://provenance.example.com` |
| `PROV_JWT_SECRET` | A generated secret (signs access tokens) |
| `PROV_CSRF_SECRET` | A generated secret |
| `PROV_CA_PASSPHRASE` | A generated secret (guard this — it encrypts the SSH CA key) |
| `POSTGRES_PASSWORD` | A generated secret |
| `PROV_BACKUP_PASSPHRASE` | A generated secret **distinct** from the CA passphrase (required in production; backups contain every at-rest secret) |
| `PROV_COOKIE_SECURE` | `true` in production (cookies only over HTTPS) |
| `PROV_WG_JUMP_ENDPOINT` | The address:port managed hosts will dial to reach the jump host (public/LAN IP or DNS + UDP port), if you use the WireGuard overlay |

> **In production the backend refuses to start on several checks.** Failing fast
> here is deliberate: each of these is a setting that would otherwise let the
> server run and break something later, somewhere else.
>
> - **Weak or missing secrets** — `PROV_JWT_SECRET` (≥32 bytes),
>   `PROV_CSRF_SECRET`, `PROV_CA_PASSPHRASE`, `PROV_AUDIT_HMAC_KEY`,
>   `PROV_ANSIBLE_RUNNER_TOKEN`.
> - **`PROV_PUBLIC_URL` still pointing at localhost.** This is the address
>   browsers and identity providers are told to use, so a wrong one boots cleanly
>   and then breaks single sign-on, passkeys and every terminal WebSocket
>   separately, none of them saying why.
> - **`PROV_COOKIE_SECURE=false` while `PROV_PUBLIC_URL` is `https://`.**
>   Session cookies would be sent without the `Secure` flag and no HSTS header
>   set. Plain `http://` is warned about rather than refused — a deployment on a
>   trusted private network genuinely cannot set `Secure`, or nobody can log in.
>
> **`.env.example` trips two of these on purpose**: it ships
> `PROV_PUBLIC_URL=http://localhost:8080` and `PROV_COOKIE_SECURE=false`, which
> are right for a laptop and wrong for a server. For a production install start
> from **`.env.production.example`** instead, which has the correct values.
>
> In production, the backend also refuses to start with weak or missing secrets. Do not
> reuse the CA passphrase as the backup passphrase — one leak would then decrypt both.

The full list of environment variables (retention windows, monitor concurrency,
metric history, rate limits, WireGuard, MFA/WebAuthn, tracing) is documented in the
[Deployment Guide](./deployment.md#3-configuration-environment).

---

## 4. Deploy the stack

For the standard single-server install (app stack + co-located jump host / VPN
server):

```bash
make up-single
```

This builds and starts PostgreSQL, Redis, the Go backend, the React frontend, the
Ansible sidecar, the Grype vulnerability-scanner sidecar, and the jump host. The
version stamped into the build is derived from the nearest git tag.

- To bring up only the base application stack (no co-located jump host — you supply
  an external one): `make up`.
- Check status any time: `make ps-single` (or `docker compose ps`).
- Tail logs: `make logs-single`.

> The Grype sidecar image is built here; its build needs internet access to install
> the scanner. The CVE database itself is **not** baked into the image — you load it
> after install (§6, and for air-gapped hosts §7).

---

> **The UI is on port 5173.** `make up-single` publishes the frontend there; the
> backend listens on 8080 bound to loopback and is reached *through* it. So with
> the example `.env` the browser wants `http://<host>:5173`, not
> `PROV_PUBLIC_URL`. For production, put your TLS reverse proxy in front of 5173
> and set `PROV_PUBLIC_URL` to the address that proxy serves — they must match,
> or sign-on and WebSockets break.

## 5. Create the first administrator (bootstrap)

Open `PROV_PUBLIC_URL` in a browser. On first run — while **no** user account exists
— Provenance shows a one-time **bootstrap** page. Create your first account there;
it becomes the super administrator.

> Bootstrap self-gates: once any user exists, the bootstrap endpoint is closed. If you
> ever need to recover from losing all administrators, see
> [Disaster Recovery](./disaster-recovery.md#recovery-scenarios).

Sign in with the account you just created. You'll be prompted to set up two-factor
authentication if your policy requires it (see the [User Guide](./user-guide.md#1-sign-in)).

---

## 6. Verify

From the host:

```bash
# Version and readiness (bound to loopback; front the API through the frontend/nginx)
curl -fsS http://localhost:8080/version   # -> {"version":"vX.Y.Z", ...}
curl -fsS http://localhost:8080/ready      # -> ok
docker compose ps                          # all services healthy/running
```

You should see your release version (not `dev`) and every service up, including
`grype-scanner`.

**Then, before your first vulnerability scan,** load the CVE database once: open the
**Vulnerabilities** page and click **Update online** (the scanner needs outbound
internet for this). The page shows the database's build date once it's loaded.

---

## 7. Air-gapped installs (offline CVE database)

If the server has no outbound internet, you can still run vulnerability scans:

1. On an internet-connected machine, download an Anchore Grype database archive.
2. On the Provenance **Vulnerabilities** page, use **Import offline** to upload that archive.

Everything else (the application, compliance scans, enrollment) works offline. See the
Administration Guide's vulnerability-scanning section for details.

---

## 8. Next steps

You now have a running Provenance. To make it useful:

1. **Enroll your first host** — [Host Enrollment Guide](./host-enrollment-guide.md).
2. **Set up users, roles, and groups** — [Administration Guide](./admin-guide.md).
3. **Configure single sign-on, notifications, and backups** — [Administration Guide](./admin-guide.md).
4. **Harden for production / internet exposure** — [Deployment Guide](./deployment.md#7-post-deploy-hardening-checklist) and [Internet Exposure](./internet-exposure.md).
5. **Know your recovery procedures before you need them** — [Break-Glass Runbook](./break-glass.md) and [Disaster Recovery](./disaster-recovery.md).

For everything the platform can do, start at the [documentation index](./README.md).
See the [CHANGELOG](./CHANGELOG.md) for what's new in each release.
