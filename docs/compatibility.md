# Compatibility, versioning and support

What Fleet Terminal promises to keep working, for how long, and what it reserves
the right to change. This is the contract behind the version number: from 1.0
onward the number is a statement about compatibility, not a changelog.

---

## Versioning

Fleet Terminal follows [Semantic Versioning](https://semver.org). Given
`MAJOR.MINOR.PATCH`:

- **PATCH** — bug fixes and security fixes. No new surface, nothing removed.
- **MINOR** — new endpoints, new fields, new settings, new features. Everything
  that worked before still works.
- **MAJOR** — a documented incompatible change to something in **What is
  covered** below.

A release is what a version number refers to: the server, the frontend it
serves, the `fleetctl` binary, the SDK and the Terraform provider are versioned
and released together.

---

## What is covered

These are the surfaces a MAJOR release is required to break:

**The REST API under `/api/v1`.** Existing endpoints keep their paths, methods,
required permissions and response shapes. Fields are added, never removed or
retyped, and never change meaning. A client that ignores unknown fields keeps
working across every MINOR release.

**Authentication.** The bearer-token scheme, the `flt_`-prefixed service-account
tokens, the refresh flow and the CSRF double-submit requirement.

**Permission names.** `Hosts.Read`, `Sessions.Connect`, `Admin.All` and the rest
keep their names and their meaning. A permission may be added; an existing one is
not repurposed.

**Configuration.** Environment variables keep their names, types and defaults. A
setting may be added, and one may be deprecated — but a deprecated setting keeps
working for the remainder of the MAJOR series.

**Database migrations.** Applied automatically on startup, forward-only, and
safe to run against a database written by any release in the same MAJOR series.

**Upgrade bundles.** A `.fleetup` bundle installs onto any earlier release in
the same MAJOR series.

**Host enrollment.** An enrolled host keeps working across upgrades of the
server without re-enrollment.

**The Go SDK and the Terraform provider.** Exported types and resource schemas
follow the same rules as the REST API.

---

## What is not covered

Changing these is not a breaking change, and they may change in any release:

- **Anything the UI renders** — layout, wording, colours, the shape of the
  frontend bundle. The API behind it is covered; the page is not.
- **Log lines and their format.** Alerting on message text is alerting on an
  implementation detail; use the audit log or the metrics.
- **Metric names not listed in the operations guide**, and the exact set of
  labels on any metric.
- **The database schema itself.** Read Fleet's tables directly and a migration
  will eventually move them under you. The REST API is the supported way to get
  at the data.
- **Internal Go packages** (`backend/internal/...`). The published SDK is the
  supported client surface.
- **The AI assistant's answers.** It is advisory by construction and its output
  is not a stable interface — see the note in the operations guide.
- **Anything documented as experimental or as a plan** (files in `docs/` ending
  in `-plan.md` describe intent, not commitments).

---

## Deprecation

Nothing covered above is removed without warning:

1. It is announced in the changelog for the release that deprecates it, with
   what replaces it.
2. It keeps working, and is documented as deprecated, for **at least two MINOR
   releases**.
3. It is removed in the next MAJOR release, never before.

A deprecated setting or endpoint that is still in use logs a warning naming its
replacement, so an operator finds out from their own logs rather than from a
failed upgrade.

---

## Supported versions

| Version | Status |
| --- | --- |
| Latest MINOR of the current MAJOR | Fixes and security fixes |
| Previous MINOR | Security fixes only, for 6 months after the next MINOR ships |
| Anything older | Unsupported — upgrade |

A security fix is issued as a PATCH on every supported line at once.

Pre-1.0 releases (`0.x`) are unsupported: `0.x` made no compatibility promise,
which is precisely what 1.0 changes.

---

## Upgrading

Upgrades are forward-only, one MAJOR series at a time, and there is no supported
downgrade — migrations do not roll back. Take a backup before upgrading; see
[disaster recovery](disaster-recovery.md) for restoring one.

Within a MAJOR series you may skip MINOR versions: migrations from any earlier
release in the series apply in order on startup. Crossing a MAJOR boundary means
going through that MAJOR's final MINOR first, so its deprecation warnings are
seen before what they warn about is gone.

---

## Reporting a compatibility break

If a MINOR or PATCH release breaks something listed under **What is covered**,
that is a bug, not a new behaviour to work around. Open an issue with the
version you upgraded from and to, and what stopped working. Security issues go
through [SECURITY.md](../SECURITY.md) instead.
