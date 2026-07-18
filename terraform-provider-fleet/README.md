# Terraform Provider for Fleet Terminal

Manage a [Fleet Terminal](https://github.com/kforbus3/Fleet-Terminal) deployment as
infrastructure-as-code: hosts, groups (including dynamic membership rules), service
accounts, and their API tokens. Built on the official Go SDK and the modern
[terraform-plugin-framework](https://github.com/hashicorp/terraform-plugin-framework).

## Authentication

The provider authenticates with a **service-account API token** (`flt_…`), issued
from **Settings → Service Accounts** in the Fleet UI. Grant the token a role with
only the permissions your configuration needs (least privilege):

- `fleet_host` → `Host.Enroll` / `Host.Edit` / `Host.Delete` / `Host.View`
- `fleet_group` → `Group.Create` / `Group.Edit` / `Group.Delete`
- `fleet_service_account` / `..._token` → `ServiceAccount.Manage`
- `data.fleet_role` → `Role.Edit`

Configure it via the provider block or environment variables:

```hcl
provider "fleet" {
  endpoint = "https://fleet.example.com" # or FLEET_URL
  # token  = "flt_..."                   # or FLEET_API_TOKEN (preferred)
}
```

## Resources & data sources

| Type | Kind | Notes |
|---|---|---|
| `fleet_host` | resource | Full CRUD + `terraform import <id>`. |
| `fleet_group` | resource | Full CRUD; add a `rule { }` block for dynamic membership. |
| `fleet_service_account` | resource | Create/Delete; **any change replaces it** (the API has no in-place update). |
| `fleet_service_account_token` | resource | Create/Revoke; the secret is stored (sensitive) in state and shown once. |
| `fleet_role` | data source | Resolve a role name to its UUID (for `role_ids`). |

See [`examples/main.tf`](./examples/main.tf) for a complete configuration.

## Building from source

This provider lives in the Fleet Terminal monorepo and builds against the local SDK
(via a `replace` directive), so build it from a checkout:

```bash
cd terraform-provider-fleet
go build -o terraform-provider-fleet
```

Install it for local use with a [dev override](https://developer.hashicorp.com/terraform/cli/config/config-file#development-overrides-for-provider-developers)
in your `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides {
    "kforbus3/fleet" = "/absolute/path/to/terraform-provider-fleet"
  }
  direct {}
}
```

Then `terraform plan` / `apply` in a configuration that declares the provider.

## Known limitations (v1)

- **Service accounts are replace-only.** The API has no update endpoint, so changing
  `username`, `display_name`, `role_ids`, or `group_ids` recreates the account (and
  invalidates its tokens). Plan carefully.
- **`role_ids` / `group_ids` are not read back.** The API returns role/group *names*,
  not the IDs the configuration uses, so out-of-band role changes are not detected.
- **Token secrets live in state.** As with most providers that create credentials,
  the token is stored (marked sensitive) in Terraform state — protect your state
  backend accordingly.

## Relationship to the SDK and CLI

The provider, the [Go SDK](../sdk), and the `fleet` CLI all speak the same REST API
with the same `flt_` token. Use the provider for declarative infrastructure, the CLI
for imperative/scripted tasks, and the SDK for custom tooling.
