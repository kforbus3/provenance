# Fleet Terminal

**Browser-based Privileged Access Management (PAM) for Linux fleets.**

Fleet Terminal gives operators secure, audited SSH access to hundreds or thousands of
Linux hosts **from the browser** — with no SSH client, VPN, WireGuard, keys, or
certificates on the user side. The browser talks only to the backend over HTTPS/WebSocket;
the **backend is the sole SSH client** and brokers every connection through a jump host and
WireGuard overlay to managed hosts.

```
Browser ──HTTPS/WS──> React SPA ──REST/WS──> Go Backend ──SSH──> Jump Host ──WireGuard──> Managed Hosts
                                                  │
                                   ┌──────────────┴───────────────┐
                                   │ SSH CA · ephemeral identities │
                                   │ RBAC · JIT approvals · audit  │
                                   └───────────────────────────────┘
```

## Why it's different

- **Ephemeral identities.** Every login mints a brand-new Ed25519 keypair **in backend RAM**
  and signs a short-lived (7-day) OpenSSH user certificate. Private keys never touch disk,
  the database, cookies, or the browser, and are zeroized on logout/idle. Certificates
  auto-renew ~24h before expiry and are revoked on session end.
- **Internal SSH Certificate Authority.** The CA private key is generated in-process,
  encrypted at rest (AES-256-GCM), and never leaves the backend. Supports rotation and
  revocation (KRL).
- **Backend-only SSH.** The browser exchanges terminal bytes over a WebSocket; it never
  speaks SSH, holds keys, or gets VPN connectivity.
- **Defense in depth.** Argon2id passwords, JWT access + rotating refresh tokens, CSRF
  double-submit, account lockout, fine-grained RBAC enforced server-side, group-based host
  authorization, just-in-time approvals, and a **hash-chained tamper-evident audit log**.

## Features

| Area | Capability |
|------|-----------|
| Access | Browser SSH terminal (xterm.js), multi-tab, full PTY, session recording & replay; **real-time dashboard** (quick-connect, live "who's connected to which host"); **Hosts/Terminals group filter** |
| Identity | Self-contained auth, Argon2id, MFA (TOTP + WebAuthn passkeys) — optional or **enforced** globally/per-user, first-run bootstrap wizard; **single sign-on (OIDC + LDAP/AD)** with auto-provisioning and group→role mapping |
| AuthZ | RBAC (built-in + custom roles), host groups **and direct user→host grants**, **root vs login-only host access** (`Host.Sudo`), just-in-time temporary access with auto-expiry |
| Hosts | Inventory + **quick-connect Terminals launcher**, live SSH health monitoring, **per-host pending package updates**, automated enrollment (password / private key / **SSH agent** / **no-install ssh-pipe** / **direct "skip-WireGuard" host**) |
| CA | **Unique ephemeral cert per (user, host)**, CA rotation, revocation, lifecycle API |
| Automation | **Ansible playbook management** (author, lint/syntax-check, run via an isolated `ansible-runner` sidecar); **scheduling** of recurring scans & playbook runs |
| Hardening | Per-IP rate limiting, idle/absolute session reaper, live-session termination, internet-exposure guide |
| Compliance | One-click **OpenSCAP** security scans per host (auto-installs scanner; CIS/STIG/… profiles) with in-UI HTML reports + offline export |
| Audit | Hash-chained audit with integrity verification + export; full auth event log; **audit forwarding to a SIEM** (syslog / HTTP JSON) |
| Resilience | **Encrypted database backups** + retention policy and **break-glass recovery** runbook |
| Notifications | Outbound **email (SMTP) + webhook** notifications on key events |
| Assistant | AI assistant aware of host inventory/metrics, **security scans, playbook runs, and pending updates** |
| Ops | Prometheus metrics, structured logs, health/ready endpoints, **System Health dashboard**, **CA-key rotation reminders**, **app-wide display timezone**, Docker/K8s/Helm/systemd artifacts |

## Quick start

Requires Docker + Docker Compose. No local Go/Node/Postgres toolchain needed.

```bash
make up        # builds & starts Postgres, Redis, backend, frontend, and the SSH test fabric
```

Then open the frontend (http://localhost:5173). On first run you'll be guided through the
**bootstrap wizard** to create the initial Super Administrator; the wizard then permanently
self-disables.

Useful targets:

```bash
make up-app    # app stack only (no SSH test fabric)
make test      # backend + frontend tests
make logs      # tail logs
make down      # stop;  make clean  # stop + remove volumes
```

## Repository layout

```
backend/    Go API server + SSH gateway (chi, pgx, x/crypto/ssh, gorilla/websocket)
frontend/   React + TypeScript + Vite + MUI + xterm.js + React Query + Zustand
deploy/     docker-compose (app + test fabric), k8s manifests, Helm chart, systemd units
docs/       architecture, API, schema, admin/user/developer/security/DR guides
scripts/    orchestration + dev helpers
```

## Architecture & docs

- [docs/architecture.md](docs/architecture.md) — components, data flows, security model
- [docs/deployment.md](docs/deployment.md) — deploy the whole system · [docs/internet-exposure.md](docs/internet-exposure.md) — internet-facing
- [docs/api.md](docs/api.md) — REST API reference · [docs/database.md](docs/database.md) — schema reference
- [docs/security-guide.md](docs/security-guide.md) · [docs/certificate-lifecycle.md](docs/certificate-lifecycle.md)
- [docs/admin-guide.md](docs/admin-guide.md) · [docs/user-guide.md](docs/user-guide.md) · [docs/host-enrollment-guide.md](docs/host-enrollment-guide.md)

## Status

Working and verified end-to-end (see `git log` for the milestone history):

- Auth (Argon2id, JWT + rotating refresh, CSRF, lockout), **MFA (TOTP + WebAuthn passkeys),
  optional or enforced** globally/per-user, first-run bootstrap
- **Single sign-on** — **OIDC** (Okta/Azure AD/Google/Keycloak/Authentik, auth-code + PKCE,
  JWKS-verified ID tokens) and **LDAP/Active Directory** (service-account lookup + user-bind),
  with auto-provisioning and **group→role mapping**; provider secrets sealed at rest
- RBAC + host groups + **direct user→host grants** + **just-in-time approvals** with auto-expiry
- Host inventory + **quick-connect Terminals launcher** with **group filter** and **per-host
  pending package updates**; **enroll hosts five ways** — SSH password, SSH private key,
  **forwarded SSH agent** (key stays local), a **no-install ssh-pipe** script, or a **direct
  "skip-WireGuard" host** (for hosts on the jump host's LAN or the box running Fleet itself).
  WireGuard-routed methods install CA trust + WireGuard and verify per-user cert login
- Internal SSH **CA + ephemeral certificates, unique per (user, host)** (in-RAM keys, 7-day,
  auto-renew, revoke via distributed KRL)
- Backend-only **browser SSH terminal** (xterm.js) through jump host + WireGuard
- **Session recording** (asciicast v2) + replay + offline export
- **Live host monitoring** (authenticated SSH health checks, no ICMP) with WebSocket push
- **Audited SFTP** file transfer (browse/upload/download/drag-and-drop, progress, cancel)
- **OpenSCAP** security scans + remediation, and **Ansible playbook management** (author,
  lint/syntax-check, run) executed through an isolated `ansible-runner` sidecar
- **Scheduling** of recurring scans & playbook runs; **outbound notifications** (email + webhook)
- **Encrypted database backups** + retention policy and a **break-glass recovery** runbook
- **Hardening for internet exposure:** per-IP rate limiting, idle/absolute session reaper,
  live-session termination on revoke, hardened production config + reverse-proxy guide
- Hash-chained **tamper-evident audit** with integrity verification, plus **audit forwarding**
  to a SIEM (syslog RFC 5424 or HTTP JSON; the local chain stays authoritative)
- **AI assistant** aware of inventory, metrics, scans, playbook runs, and pending updates
- Admin suite (users/roles/groups/settings), **System Health dashboard** with **CA-key
  rotation reminders** (`FLEET_CA_ROTATE_AFTER`), **app-wide display timezone**, Prometheus
  metrics, health/ready
- Docker Compose + local SSH test fabric; K8s manifests, Helm chart, systemd units

Documented for incremental deepening: distributed tracing (OTel), SAML SSO.

See [docs/deployment.md](docs/deployment.md) to deploy and [docs/operations.md](docs/operations.md)
for day-to-day flows (enroll, connect, transfer, MFA).

## License

Internal / proprietary (adjust as appropriate for your organization).
