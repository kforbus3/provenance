# Contributing to Fleet Terminal

Thanks for your interest in improving Fleet Terminal. This guide covers how to get
a development environment running, the checks your change must pass, and how to
submit it.

By contributing, you agree that your contributions are licensed under the project's
[Apache License 2.0](LICENSE).

## Reporting bugs and requesting features

- **Security vulnerabilities:** do **not** open a public issue — follow
  [SECURITY.md](SECURITY.md).
- **Bugs / features:** open a GitHub issue. For bugs, include the affected
  component, steps to reproduce, what you expected, and what happened (logs,
  screenshots, and the commit you're on all help).

## Prerequisites

The toolchain is fully Dockerized, so you don't need Go or PostgreSQL installed
locally — only:

- **Docker** + **Docker Compose**
- **Node 22+** and npm (for frontend work; the backend builds inside a container)
- **make**

The backend targets **Go 1.23**.

## Running the stack

```bash
make up        # build & start the full stack + local SSH test fabric
make trust     # one-time: seed the test-fabric nodes with the backend CA
make ps        # show running services
make logs      # tail logs
make down      # stop the stack (data volumes preserved)
make clean     # stop and DESTROY data volumes
```

On first launch the app presents a **bootstrap wizard** that creates the initial
Super Admin and then permanently self-disables. `make up-app` starts only the
application stack (no test fabric); `make help` lists every target.

## Making a change

1. **Branch** off `main`: `git checkout -b my-change`.
2. Make focused commits. Match the style of the surrounding code — the backend is
   idiomatic Go (`go vet`-clean), the frontend is TypeScript + React + MUI with no
   `tsc` errors.
3. Keep changes scoped. Unrelated refactors belong in their own PR.
4. Update docs under [`docs/`](docs/) when you change behavior, and add a migration
   under `backend/internal/db/migrations/` (idempotent — `IF NOT EXISTS` /
   `ON CONFLICT`) when you change the schema. Never edit an already-released migration.

### Security-sensitive areas

Changes to authentication, RBAC, the SSH CA / certificate issuance, the gateway,
secret-at-rest handling, or the audit log get extra scrutiny. Call out the security
implications in your PR description. Never log secrets, certificates, or private
keys, and never send TOTP secrets or private keys to third-party services.

## Required checks

Run these before opening a PR — they mirror the CI workflow
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

```bash
# Backend (runs in a throwaway Go container)
make backend-build     # go build ./...
make lint              # go vet ./...
make backend-test      # go test ./...
make tidy              # go mod tidy (commit the resulting go.mod/go.sum)

# Frontend
cd frontend
npm install
npx tsc -b             # typecheck
npm run build          # production build
npm run lint           # eslint
npm test               # vitest
```

End-to-end and load tests need the stack running:

```bash
make e2e               # Playwright e2e against the running stack
make load              # k6 load smoke test
```

CI must be green before a PR is merged.

## Submitting a pull request

- Target `main` and give the PR a clear title and description: what changed, why,
  and how you tested it.
- Link the issue it addresses (`Fixes #123`).
- Make sure CI passes and docs are updated.

Maintainers review for correctness, security, and consistency with the existing
architecture. Thanks for contributing!
