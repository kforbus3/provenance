# Automation: SDK & CLI

Fleet Terminal can be driven as code. Alongside the [REST API](./api.md), an
official **Go SDK** and a **`fleet` command-line tool** let you manage inventory
and access from CI/CD pipelines, scheduled jobs, and your own tooling — without a
browser and without database access.

- **Audience:** platform / DevOps engineers automating fleet management.
- **Result:** scripted host registration, group and access management, scoped
  credential issuance, vulnerability scans, and evidence reports.

> `fleet` (the automation CLI documented here) is distinct from `fleetctl`, the
> on-host break-glass tool that connects directly to the database for recovery.
> Use `fleet` for day-to-day automation; see the Operations guide for `fleetctl`.

---

## 1. Authenticate

Automation authenticates with a **service-account API token** — never a personal
login.

1. **Settings → Service Accounts → New.** Give it a role scoped to only the
   permissions the automation needs (least privilege).
2. **Create a token** on that account. The secret (prefixed `flt_`) is displayed
   **once** — capture it into your secret store.
3. Provide the deployment URL and token via environment variables:

```bash
export FLEET_URL="https://fleet.example.com"
export FLEET_API_TOKEN="flt_xxxxxxxxxxxxxxxxxxxx"
```

Every request is authorized server-side against the token's role, so a leaked or
over-scoped token is contained by the permissions you granted it. Set an
expiry (`--expires-days`) on tokens used by short-lived jobs.

---

## 2. The `fleet` CLI

Install:

```bash
go install github.com/kforbus3/Fleet-Terminal/sdk/cmd/fleet@latest
```

Verify the token and see its effective permissions:

```bash
fleet whoami
```

Common tasks:

```bash
# Inventory (table, or JSON for jq)
fleet hosts list
fleet hosts list --json | jq -r '.[] | select(.enrolled==false) | .hostname'

# Register a host
fleet hosts create --hostname db-02 --env prod --tags db,postgres --ssh-user fleet

# Dynamic group — membership (and thus access) follows host tags automatically
fleet groups create --name prod-databases --env prod --tag-all db

# Vulnerability scan a whole group, then export a CVE report
fleet vuln scan --group "$GROUP_ID"
fleet report vulnerabilities --from 2026-01-01 -o vulns.csv
```

Add `--json` to read commands for machine-readable output. Exit codes are `0`
(success), `1` (API/runtime error), and `2` (usage error), so failures stop a
pipeline.

### Issuing a token from a pipeline

```bash
sa=$(fleet sa create --username ci-bot --roles "$ROLE_ID" --json | jq -r .id)
fleet tokens create "$sa" --name gitlab-ci --expires-days 90 > ci_token.txt
```

The token secret is written to **stdout** (a human-readable note goes to stderr),
so redirecting stdout captures exactly the secret.

---

## 3. The Go SDK

Add it to a module:

```bash
go get github.com/kforbus3/Fleet-Terminal/sdk@latest
```

```go
c, err := fleet.New(os.Getenv("FLEET_URL"), fleet.WithToken(os.Getenv("FLEET_API_TOKEN")))
if err != nil {
    log.Fatal(err)
}
hosts, err := c.ListHosts(ctx, fleet.ListOptions{Limit: 100})
```

Non-2xx responses return an `*fleet.APIError` with the status and server message;
`fleet.IsNotFound` and `fleet.IsUnauthorized` classify the common cases. The SDK
depends only on the Go standard library. Full reference and examples are in the
[SDK README](https://github.com/kforbus3/Fleet-Terminal/tree/main/sdk).

---

## 4. What is covered

The SDK and CLI wrap the **inventory and access-management** surface: hosts (create,
read, update, delete, group membership), users (read), roles and permissions
(read), groups (create/update/delete, including dynamic rules), service accounts
and tokens (create/read/delete), vulnerability scans (trigger/list/get), and CSV
evidence reports.

Interactive surfaces — terminal sessions, file transfer, and session replay — are
intentionally **not** scripted here; they are interactive rather than declarative.
For any endpoint not wrapped by the SDK, call it directly per the
[API Reference](./api.md).

---

## 5. Terraform

A **Terraform provider** (`terraform-provider-fleet`, in the repository) manages
Fleet as declarative infrastructure over the same API and token model. It exposes:

- `fleet_host` — managed hosts (full CRUD + import)
- `fleet_group` — groups, including dynamic membership rules
- `fleet_service_account` and `fleet_service_account_token` — automation identities
  and their API tokens
- `fleet_role` (data source) — resolve a role name to its UUID

```hcl
provider "fleet" {
  endpoint = "https://fleet.example.com" # or FLEET_URL
  # token via FLEET_API_TOKEN
}

resource "fleet_host" "web" {
  hostname    = "web-01"
  environment = "production"
  tags        = ["web", "prod"]
}
```

Authenticate with a service-account token scoped to only the permissions your
configuration needs. See the provider's README for building, installing (dev
overrides), the full example, and current limitations.
