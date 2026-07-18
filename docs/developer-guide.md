# Fleet Terminal — Developer Guide

This guide covers building, running, and extending Fleet Terminal. Everything
runs through Docker, so **no local Go, Node, or PostgreSQL toolchain is required.**

## Layout

```
backend/                Go service (chi, pgx)
  cmd/fleetd/           main entrypoint
  internal/
    api/                router wiring (server.go), helpers, system health (health.go)
    app/                Deps container (shared services)
    httpx/              shared HTTP helpers (WriteJSON/WriteError/Decode/ParseID/Audit)
    auth/               authN/Z: tokens, middleware, password policy
                        (incl. oidc.go = OIDC SSO, ldap.go = LDAP/AD)
    bootstrap/          first-run wizard
    hosts/              host inventory (canonical HTTP module)
    enrollment/         host enrollment (5 methods, incl. skip-WireGuard)
    admin/              users / roles / groups / settings
    auditapi/           audit list / verify / export
    auditfwd/           forward audit events to syslog / HTTP (SIEM) via the store's audit sink
    sessionsapi/        recorded session replay
    approvals/          just-in-time access workflow
    serviceaccounts/    non-human identities + API token auth (REST-only)
    certificates/       CA + certificate lifecycle
    terminal/           WebSocket SSH terminal
    shadow/             live read-only session shadowing (Session.Watch)
    sftp/               audited SFTP file transfer
    scan/               OpenSCAP scans + remediation
    vulnscan/           CVE vulnerability scans (via grype-scanner sidecar)
    playbook/           Ansible playbook author/lint/run (via runner sidecar)
    scheduler/          recurring scans & playbook runs
    notify/             outbound email + webhook notifications
    reports/            compliance CSV exports (Audit.View)
    reportsched/        scheduled report delivery (CSV email attachments)
    insights/           explainable fleet-health issues + disk-runway projection
    digest/             scheduled fleet-health digests (via notify)
    backup/             encrypted DB backups + retention
    system/             background-job status, operational settings
    monitor/            authenticated SSH health checks, pending updates
    assistant/          AI assistant (inventory/metrics/scans/runs/updates/insights)
    ca/ identity/ sshgw/ recorder/ ws/   SSH + WebSocket plumbing
                        (incl. livesessions.Broker = session-shadow fan-out)
    store/              SQL data access (one file per aggregate)
    db/migrations/      SQL migrations (applied on start)
    config/ models/ metrics/ telemetry/
frontend/               React + Vite SPA (nginx in prod)
deploy/compose/         docker-compose.yml (local stack, incl. sidecars)
deploy/ansible-runner/  Python/Ansible sidecar (playbook lint + run)
deploy/grype-scanner/   Anchore Grype sidecar (CVE scanning; grype-db volume)
deploy/k8s/             Kubernetes manifests
docs/                   this documentation
Makefile                developer entrypoints
```

The SSO integrations pull in a few third-party libraries (run `make tidy` after
changing them): `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2` for the
OIDC authorization-code/PKCE flow, and `github.com/go-ldap/ldap/v3` for LDAP/AD
sign-in.

## Prerequisites

- Docker + Docker Compose.
- That's it. The Makefile shells into throwaway `golang:1.23-alpine` and
  `node:22-alpine` containers for builds and tests.

## Quick start

```sh
make env      # create .env from .env.example if missing
make up       # build & start the full stack + test fabric
make ps       # show running services
make logs     # tail logs
```

`make up` brings up PostgreSQL, Redis, the backend, the frontend, the
**`ansible-runner`** sidecar (Python/Ansible service the `playbook` module calls
to lint and run playbooks — built from `deploy/ansible-runner`), and the local
**test fabric** (jump host + managed hosts used for end-to-end SSH testing).
Use `make up-app` to start only the application stack without the test fabric.

Once the stack is healthy, open the frontend (Vite dev server, default
`http://localhost:5173`; the backend listens on `http://localhost:8080`) and
complete the **bootstrap** flow (see [Admin Guide](./admin-guide.md)).

## Common Makefile targets

| Target | What it does |
|--------|--------------|
| `make help` | List all targets |
| `make env` | Create `.env` from `.env.example` if missing |
| `make up` | Build & start full stack + test fabric |
| `make up-app` | Start only the application stack |
| `make down` | Stop the stack |
| `make clean` | Stop and remove volumes (**destroys data**) |
| `make logs` / `make ps` | Tail logs / show services |
| `make build` | Build all images |
| `make backend-build` | Compile the backend in a throwaway Go container |
| `make test` | Run all tests (`backend-test` + `frontend-test`) |
| `make backend-test` | Go unit + integration tests |
| `make frontend-test` | Frontend unit tests |
| `make lint` | `go vet` |
| `make tidy` | `go mod tidy` |

## Building & testing the backend

```sh
make backend-build      # compile everything
make backend-test       # go test ./...
make test               # backend + frontend
```

To compile a single package directly (the pattern used in CI for module workers):

```sh
docker run --rm -v "$PWD/backend:/src" -w /src golang:1.23-alpine \
  sh -c "apk add --no-cache git >/dev/null 2>&1 && GOFLAGS=-mod=mod go build ./internal/hosts/..."
```

## Configuration

All configuration is environment-driven (`backend/internal/config/config.go`),
so the same binary runs identically across Docker, Kubernetes, and systemd. Key
variables (see `.env.example` and the [Admin Guide](./admin-guide.md) for the
full list):

| Variable | Default | Purpose |
|----------|---------|---------|
| `FLEET_ENV` | `development` | `development` relaxes secret validation |
| `FLEET_HTTP_ADDR` | `:8080` | listen address |
| `FLEET_PUBLIC_URL` | `https://localhost:8443` | external base URL (cookies/CORS). In dev you reach the Vite frontend at `http://localhost:5173`, which proxies to the backend. |
| `FLEET_DATABASE_URL` | `postgres://fleet:fleet@postgres:5432/fleet?sslmode=disable` | DB DSN |
| `FLEET_MIGRATE_ON_START` | `true` | run migrations at boot |
| `FLEET_JWT_SECRET` | — | HMAC secret for access tokens (≥32 bytes in prod) |
| `FLEET_CSRF_SECRET` | — | CSRF secret (≥16 bytes in prod) |
| `FLEET_CA_PASSPHRASE` | — | encrypts the CA private key (≥16 bytes in prod) |
| `FLEET_COOKIE_SECURE` | `true` | set `false` only for non-HTTPS local dev |
| `FLEET_JUMP_HOST` / `FLEET_JUMP_USER` | `jumphost:22` / `fleet` | SSH egress |
| `FLEET_USER_CERT_TTL` | `168h` (7d) | ephemeral user cert lifetime |
| `FLEET_CERT_RENEW_BEFORE` | `24h` | renew certs this far ahead of expiry |
| `FLEET_RECORDING_DIR` | `/var/lib/fleet/recordings` | session recordings |

In `development`, missing secrets fall back to **insecure deterministic
defaults** so the stack boots — never run that way in production. In
`production`, startup fails if `FLEET_JWT_SECRET`, `FLEET_CSRF_SECRET`, or
`FLEET_CA_PASSPHRASE` are missing/too short.

## Adding a backend HTTP module

Modules follow the canonical shape in `internal/hosts/handlers.go`:

1. Create `internal/<pkg>/<pkg>.go`. Expose:
   ```go
   func Mount(r chi.Router, d *app.Deps) { … }
   ```
2. Construct your handler from `*app.Deps` only (`d.Store`, `d.Cfg`, `d.Log`,
   `d.Auth`, and the SSH services `d.CA` / `d.Gateway`). This avoids import cycles.
3. Gate **every** route:
   ```go
   r.Group(func(pr chi.Router) {
       pr.Use(d.Auth.RequireAuth)
       pr.With(d.Auth.RequirePermission("Host.View")).Get("/things", h.list)
   })
   ```
4. Get the caller with `auth.MustPrincipal(r)`.
5. Use **only parameterized SQL** via the store. If you need a new query, add a
   method to the matching `internal/store/*.go` file.
6. Use the shared **`internal/httpx`** helpers rather than per-package copies for
   responses, decoding, and IDs — `httpx.WriteJSON` / `httpx.WriteError`,
   `httpx.Decode(w, r, &req)`, and `httpx.ParseID(w, r)` for the `{id}` URL param.
7. Audit every state change. Newer handlers call `httpx.Audit`, which wraps the
   best-effort append:
   ```go
   httpx.Audit(r, d.Store, models.AuditEvent{
       ActorID: &p.UserID, ActorName: p.Username, Action: "thing.create",
       TargetKind: "thing", TargetID: id.String(), Detail: map[string]any{…},
   })
   ```
8. Mount it from the router seam in `internal/api/server.go`
   (`registerRoutes` / `mountModules`), e.g. `mything.Mount(r, deps)`.

Match the existing code style exactly: package doc comment, the shared
`internal/httpx` helpers (not per-package `writeJSON` / `writeError` copies),
request structs with `json:"…"` tags, and best-effort audit/event writes via
`httpx.Audit`.

## Frontend

The SPA lives in `frontend/src` (React + Vite, Zustand stores, an `api/` client
layer mirroring the REST modules). `VITE_API_BASE` points the client at the
backend. Run `make frontend-test` for unit tests.

## Releasing

CI builds the backend and frontend images. Configuration is environment-driven,
so promotion between environments is a matter of swapping env values and secrets;
see [deploy/k8s](../deploy/k8s) for Kubernetes manifests and the
[Disaster Recovery guide](./disaster-recovery.md) for backup/restore.
