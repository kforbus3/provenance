# Multi-Tenancy (MSP) — Design & Phased Plan

Status: **P0 (RLS foundation) + P1 (tenant management, auth scoping, provider console)
shipped.** Opt-in via `FLEET_MULTI_TENANCY` (default **off**); with the flag off, Fleet
is byte-for-byte single-tenant as today. Built incrementally on `main`.

**Proven end-to-end** (real API, non-superuser DB role): a provider admin creates a
customer tenant, switches into it, and each tenant's hosts/data are fully isolated —
the provider cannot see a customer's hosts and vice versa; an unscoped request sees
nothing (fail closed).

## Enabling it

1. Set `FLEET_MULTI_TENANCY=true`.
2. **The app's database role MUST be a non-superuser** (Postgres superusers and
   `BYPASSRLS` roles ignore row-level security even when it is FORCEd, so isolation would
   silently not apply). Create a dedicated non-superuser role with `USAGE` on the schema
   and privileges on the tables, run migrations as the owner, and point
   `FLEET_DATABASE_URL` at the non-superuser role for serving.
3. Existing data lands in the seeded **Provider** tenant; its admins get a **Tenants**
   console (provider console) to create customer tenants and switch into them. A provider
   admin acting inside a customer sends `X-Fleet-Tenant: <id>` (the UI's tenant switcher).

Until every subsystem is covered (see phases), treat the flag as **experimental** and do
not enable it against real multi-customer data.

## Goal

Let one Fleet deployment serve multiple isolated customer **tenants**, so an MSP can
operate many customers from a single pane of glass. Data belonging to one tenant must
never be visible to another.

## Model (decided)

- **Row-level isolation:** a `tenant_id` column on every tenant-scoped table; every
  query is scoped to the caller's tenant. One deployment, one database.
- **MSP hierarchy (recommended, adopted):** *provider staff manage many customer
  tenants.*
  - A special **provider tenant** (the MSP itself). Users in it with a new
    `Tenant.Manage` permission are **provider admins**: they create/administer customer
    tenants and can act **within** a selected customer tenant (context switch), with
    every cross-tenant action audited.
  - Each **customer tenant** has its own hosts, users, groups, credentials, sessions,
    etc. Customer users are **hard-scoped** to their own tenant and can never see or
    reach another tenant's data — enforced in the backend, not the UI.
  - Existing super-admins live in the provider tenant; existing single-tenant installs
    become "one customer tenant = the default tenant".

## The flag-off guarantee

`FLEET_MULTI_TENANCY=false` (default): all rows belong to a single seeded **default
tenant**, and **no query applies tenant scoping** — the code paths added for tenancy are
inert. A non-multi-tenant deployment is unchanged. Every phase must preserve this.

## Enforcement strategy (avoiding leakage)

Row-level scoping is only as safe as its weakest query. To make "every query is scoped"
enforceable rather than hopeful:

1. **Tenant context on the principal.** Auth resolves the caller's effective `TenantID`
   (their own tenant, or a provider admin's selected customer tenant). It flows through
   `context.Context`.
2. **Scope at the store boundary.** The `store` layer takes the tenant from context and
   adds `AND tenant_id = $tenant` to reads and sets it on writes. Centralize via helpers
   so individual call sites can't forget.
3. **Defense in depth:** a Postgres `RLS` (row-level security) policy per table keyed on
   a `SET LOCAL app.tenant_id`, so even a query that forgets the WHERE clause returns
   nothing cross-tenant. (Later phase — belt to the store-layer braces.)
4. **Isolation tests** per subsystem: seed two tenants, assert tenant A never sees B.

## Phases

- **P0 — RLS foundation (DONE).** Config flag; `tenants` table + seeded provider tenant;
  `tenant_id` + `ENABLE/FORCE ROW LEVEL SECURITY` + isolation policy on ~50 tenant-scoped
  tables (migration 0051); the `app.tenant_id` GUC set per connection by a pgxpool hook
  from the request context, so **every existing query is scoped with no per-query change**;
  `Tenant.Manage` permission. Flag off → the hook sets `bypass` → unchanged. **Because P2/P3
  scoping is achieved by RLS at P0, the whole table set is covered now, not incrementally.**
- **P1 — Tenant management + auth scoping + provider console (DONE).** `Principal.TenantID`;
  RequireAuth resolves the principal cross-tenant (bypass) then scopes the request to the
  caller's tenant; provider admins switch into a customer via `X-Fleet-Tenant`; pre-auth
  routes (login/SSO/bootstrap) bypass; tenant CRUD API (provider-admin gated, audited) +
  a **Tenants** console UI with a context switcher.
- **P2/P3 — Table coverage (DONE at P0 via RLS).** The ~50 tenant-scoped tables listed in
  migration 0051 (identity, hosts+facts, sessions/recordings/certs, audit, automation,
  vault, scanning, assistant, reviews) are all isolated by the RLS policies. Remaining:
  audit any code path that runs its own goroutine with a fresh context so it re-carries
  the tenant (enrollment/terminal async work), and confirm no tenant-scoped table was
  missed.
- **P4 — Provider console + context switch.** Provider admins list all tenants, switch
  into a customer context (audited), cross-tenant roll-ups; customer users hard-locked.
- **P5 — Polish.** Per-tenant branding/settings, per-tenant quotas, tenant lifecycle
  (suspend/delete with cascade), docs, and a readiness/enforcement self-check.

## Non-goals (for now)

Per-tenant separate databases or schemas (we chose row-level); per-tenant separate jump
hosts / overlays (a customer's hosts still enroll through the shared jump host — network
isolation between customers' managed hosts is a later, separate concern).

## Security note

Until P2+P3 complete, the flag does **not** provide full isolation and must be treated as
**experimental** — do not enable it against real multi-customer data until the readiness
self-check (P5) reports every tenant-scoped table covered.
