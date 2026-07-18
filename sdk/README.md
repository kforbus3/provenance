# Fleet Terminal Go SDK + `fleet` CLI

Official Go client and command-line tool for the Fleet Terminal API. Manage your
fleet as code — hosts, groups, users, roles, service accounts, tokens,
vulnerability scans, and compliance reports — from CI/CD, cron jobs, and your own
tooling.

- **Dependency-free.** The SDK uses only the Go standard library.
- **Token-authenticated.** Authenticates with a service-account API token
  (`flt_…`), the same credential the web UI issues under **Settings → Service
  Accounts**. No database access, no interactive login.
- **`fleet` vs `fleetctl`.** `fleet` (this tool) is the remote, token-authenticated
  automation client. `fleetctl` is the separate on-host break-glass tool that talks
  to the database directly for recovery. Use `fleet` for day-to-day automation.

## Install

### SDK

```bash
go get github.com/kforbus3/Fleet-Terminal/sdk@latest
```

### CLI

```bash
go install github.com/kforbus3/Fleet-Terminal/sdk/cmd/fleet@latest
```

This installs a `fleet` binary into `$(go env GOPATH)/bin`.

## Authentication

1. In the web UI, go to **Settings → Service Accounts**, create a service account,
   and grant it a role scoped to only the permissions it needs (least privilege).
2. Create an API token on that account — the secret (`flt_…`) is shown **once**.
3. Provide it to the SDK/CLI:

```bash
export FLEET_URL="https://fleet.example.com"
export FLEET_API_TOKEN="flt_xxxxxxxxxxxxxxxxxxxx"
```

Verify:

```bash
fleet whoami
```

## CLI usage

```
fleet <command> [subcommand] [flags]

  version                              deployment version
  whoami                               identity + permissions of the token
  hosts list | get <id> | delete <id>
  hosts create --hostname <h> [--env prod] [--tags a,b] [--ssh-user fleet]
  hosts add-group <hostId> <groupId>   |  hosts rm-group <hostId> <groupId>
  groups list | delete <id>
  groups create --name <n> [--tag-all a,b] [--tag-any a,b] [--env e]   (dynamic if any rule flag set)
  users list
  roles list
  service-accounts list | delete <id>       (alias: sa)
  service-accounts create --username <u> [--roles id,id] [--groups id,id]
  tokens list <saId>
  tokens create <saId> --name <n> [--expires-days N]
  tokens revoke <saId> <tokenId>
  vuln scan --host <id> | --group <id>
  vuln list [--host <id>] | vuln latest | vuln get <scanId>
  report <access|audit|certificates|scans|vulnerabilities> [--from D] [--to D] [-o file.csv]

Add --json to most read commands for raw JSON output.
```

### Examples

```bash
# Inventory as a table, or as JSON for jq
fleet hosts list
fleet hosts list --json | jq '.[] | select(.enrolled==false) | .hostname'

# Register a host
fleet hosts create --hostname db-02 --env prod --tags db,postgres --ssh-user fleet

# A dynamic group whose membership follows tags (no manual upkeep)
fleet groups create --name prod-databases --env prod --tag-all db

# Issue a scoped token for a CI job (secret prints to stdout, once)
sa=$(fleet sa create --username ci-bot --roles "$ROLE_ID" --json | jq -r .id)
fleet tokens create "$sa" --name gitlab-ci --expires-days 90 > ci_token.txt

# Kick a vulnerability scan across a group and pull the report
fleet vuln scan --group "$GROUP_ID"
fleet report vulnerabilities --from 2026-01-01 -o vulns.csv
```

Exit codes: `0` success, `1` runtime/API error, `2` usage error. On a 401/403 the
CLI prints a hint to check the token and its permissions.

## SDK usage

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	fleet "github.com/kforbus3/Fleet-Terminal/sdk"
)

func main() {
	c, err := fleet.New(os.Getenv("FLEET_URL"), fleet.WithToken(os.Getenv("FLEET_API_TOKEN")))
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	hosts, err := c.ListHosts(ctx, fleet.ListOptions{Limit: 100})
	if err != nil {
		log.Fatal(err)
	}
	for _, h := range hosts {
		fmt.Printf("%s\t%s\tenrolled=%t\n", h.Hostname, h.Environment, h.Enrolled)
	}
}
```

### Error handling

Non-2xx responses return an `*APIError` carrying the status and the server's
message. Helpers classify common cases:

```go
_, err := c.GetHost(ctx, id)
if fleet.IsNotFound(err) {
	// 404
}
if fleet.IsUnauthorized(err) {
	// 401/403 — missing, expired, or under-scoped token
}
var apiErr *fleet.APIError
if errors.As(err, &apiErr) {
	log.Printf("HTTP %d: %s", apiErr.StatusCode, apiErr.Message)
}
```

### Options

- `WithToken(string)` — the `flt_` bearer token.
- `WithHTTPClient(*http.Client)` — custom timeouts, proxy, or TLS config.
- `WithUserAgent(string)` — override the `User-Agent`.

`New` accepts the base URL with or without a trailing `/api/v1`, and defaults the
scheme to `https://` if omitted.

## Coverage

The SDK wraps the inventory and access-management surface of the API: hosts (CRUD
+ group membership), users (read), roles & permissions (read), groups (CRUD incl.
dynamic rules), service accounts and tokens (CRUD), vulnerability scans
(trigger/list/get), and CSV evidence reports. Live/interactive surfaces (terminal
sessions, file transfer, session replay) are intentionally out of scope — those
are interactive, not declarative. For any endpoint not yet wrapped, see the
[API Reference](../docs/api.md).

## Permissions

Every call is authorized server-side against the token's service-account role.
Grant only what a given automation needs — e.g. a scanner bot needs `Host.Scan`
and `Host.View`; an inventory sync needs `Host.View`/`Host.Enroll`/`Host.Edit`.
See the API Reference for the permission each endpoint requires.
