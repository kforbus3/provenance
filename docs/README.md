# Moorgate — Documentation

Moorgate is a Go + React Privileged Access Management (PAM) platform for
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
| [installation.md](./installation.md) | operators | Install and stand up Moorgate from scratch: prerequisites, config, first boot |
| [deployment.md](./deployment.md) | operators | Deploy the whole system: config, local + production stack |
| [internet-exposure.md](./internet-exposure.md) | operators / security | Exposing the UI to the internet behind a reverse proxy + MFA |
| [operations.md](./operations.md) | operators | Day-to-day flows: enroll, connect, transfer, approvals, MFA |
| [architecture.md](./architecture.md) | everyone | Component diagram, data flows, security model |
| [api.md](./api.md) | integrators | REST + WebSocket endpoint reference by module |
| [compatibility.md](./compatibility.md) | integrators / operators | What a version number promises: API stability, deprecation, supported releases, upgrades |
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

### Enterprise & platform features

These reference docs cover the enterprise capabilities layered on top of core SSH
brokering:

| Doc | Audience | What it covers |
|-----|----------|----------------|
| [access-policies.md](./access-policies.md) | security / admins | Attribute-based access control (ABAC) layered on RBAC to deny connections by context |
| [automation.md](./automation.md) | integrators / operators | Driving Moorgate as code with the Go SDK and the `fleet` CLI |
| [behavior-analytics.md](./behavior-analytics.md) | security | UEBA: explainable, ML-free detection of access patterns deviating from a user's baseline |
| [database-broker.md](./database-broker.md) | operators / security | Brokered privileged access to databases with vaulted credentials, run through the jump host |
| [kubernetes.md](./kubernetes.md) | operators / security | Brokered Kubernetes access via an authenticating proxy with a vaulted bearer token |
| [external-secrets.md](./external-secrets.md) | operators / security | External-backed vault credentials fetched on demand from your secrets manager |
| [kms.md](./kms.md) | operators / security | Protecting the master key with an external KMS / HSM |
| [itsm.md](./itsm.md) | operators / admins | ITSM integration (ServiceNow / Jira): open change/incident tickets for JIT access |
| [federation.md](./federation.md) | operators | Multi-site federation: a hub managing many independent site instances |
| [high-availability.md](./high-availability.md) | operators | Running multiple backends behind a load balancer for redundancy and rolling upgrades |

### Design & planning records

Design records for larger features — kept for history; check the status line at the
top of each for what has shipped:

| Doc | What it covers |
|-----|----------------|
| [fips-mode-plan.md](./fips-mode-plan.md) | FIPS mode design & migration (opt-in, P0–P4 shipped) |
| [multi-tenancy-plan.md](./multi-tenancy-plan.md) | MSP row-level multi-tenancy design & phased plan (P0–P1 shipped) |
| [windows-thirdparty-cve-plan.md](./windows-thirdparty-cve-plan.md) | Windows third-party application CVE coverage (shipped, v0.23.x) |

## Key make targets

Run `make help` for the full list. Highlights: `make up` (full stack + test
fabric) / `make up-app` (app only) / `make up-single` (single-server production:
app + co-located jump host), `make down`, `make clean` (destroys data),
`make logs`, `make ps`,
`make backend-build`, `make backend-test`, `make frontend-test`, `make test`,
`make lint`, `make tidy`.
