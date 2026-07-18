# Fleet Terminal — Documentation

Fleet Terminal is a Go + React Privileged Access Management (PAM) platform for
browser-based SSH: ephemeral, in-RAM SSH certificates, a hardened jump-host /
WireGuard egress path, backend-authoritative RBAC, and a tamper-evident,
hash-chained audit log.

## Getting started

Everything runs in Docker — no local Go/Node/Postgres toolchain needed.

```sh
make env      # create .env from .env.example
make up       # build & start the full stack + test fabric
make test     # run backend + frontend tests
```

Then open the frontend and complete the one-time **bootstrap** wizard to create
the first Super Administrator. See the [Administrator Guide](./admin-guide.md).

## Contents

| Doc | Audience | What it covers |
|-----|----------|----------------|
| [installation.md](./installation.md) | operators | Install and stand up Fleet Terminal from scratch: prerequisites, config, first boot |
| [deployment.md](./deployment.md) | operators | Deploy the whole system: config, local + production stack |
| [internet-exposure.md](./internet-exposure.md) | operators / security | Exposing the UI to the internet behind a reverse proxy + MFA |
| [operations.md](./operations.md) | operators | Day-to-day flows: enroll, connect, transfer, approvals, MFA |
| [architecture.md](./architecture.md) | everyone | Component diagram, data flows, security model |
| [api.md](./api.md) | integrators | REST + WebSocket endpoint reference by module |
| [database.md](./database.md) | developers / DBAs | Table-by-table schema reference |
| [admin-guide.md](./admin-guide.md) | administrators | Bootstrap, users/roles/groups, host access, settings |
| [user-guide.md](./user-guide.md) | end users | Signing in, 2FA, connecting, files, approvals, replay |
| [developer-guide.md](./developer-guide.md) | developers | Build/test, layout, adding modules |
| [host-enrollment-guide.md](./host-enrollment-guide.md) | operators | Enrolling hosts (5 methods, incl. direct skip-WireGuard), authorization |
| [security-guide.md](./security-guide.md) | security | Controls, MFA, rate limiting, hardening, checklist |
| [certificate-lifecycle.md](./certificate-lifecycle.md) | operators | CA, issuance, renewal, revocation, rotation |
| [disaster-recovery.md](./disaster-recovery.md) | operators | Backup, restore, recovery scenarios |
| [break-glass.md](./break-glass.md) | operators / security | Emergency recovery runbook: encrypted backups + break-glass access |
| [CHANGELOG.md](./CHANGELOG.md) | everyone | Release-by-release history of features and changes |

### Newer feature areas

Beyond core SSH brokering, the platform now also covers: **Ansible playbook
management** (author / lint / run via the `ansible-runner` sidecar) and
**scheduling** of recurring scans, playbook runs, and vulnerability scans (see
[architecture.md](./architecture.md) for the runner data flow); **CVE
vulnerability scanning** (Anchore Grype in a `grype-scanner` sidecar, with a
fleet roll-up and online/offline CVE-database management); **service accounts +
API tokens** for automation over the REST API; **outbound notifications** (email
+ webhook + PagerDuty / Opsgenie / Microsoft Teams, severity-gated); **CSV
compliance reports** (access / audit / certificate / scan / vulnerability) with
optional **scheduled email delivery**; **live session shadowing** (read-only,
audited four-eyes viewing of an active session); **dynamic host groups** whose
membership follows a rule over host attributes; **encrypted database backups**
with a **break-glass recovery** runbook (see [break-glass.md](./break-glass.md));
a deepened **AI assistant** — multi-turn conversation memory, **fleet insights**
("what's wrong with the fleet?" / disk-runway projections), and scheduled
**health digests** — aware of inventory, metrics, security scans, playbook runs,
and pending package updates; an **app-wide display timezone**; and **per-host
pending package updates** surfaced in the inventory.

## Key make targets

Run `make help` for the full list. Highlights: `make up` (full stack + test
fabric) / `make up-app` (app only) / `make up-single` (single-server production:
app + co-located jump host), `make down`, `make clean` (destroys data),
`make logs`, `make ps`,
`make backend-build`, `make backend-test`, `make frontend-test`, `make test`,
`make lint`, `make tidy`.
