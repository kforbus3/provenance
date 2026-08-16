---
page_title: "Fleet Terminal Provider"
description: |-
  Manage a Fleet Terminal deployment (hosts, groups, service accounts, tokens)
  as infrastructure-as-code.
---

# Fleet Terminal Provider

The Fleet provider manages a [Fleet Terminal](https://github.com/kforbus3/Fleet-Terminal)
Privileged Access Management deployment as code: hosts, groups (including dynamic
membership rules), service accounts, and their API tokens.

It authenticates with a **service-account API token** (`flt_…`), issued from
**Settings → Service Accounts** in the Fleet UI. Grant the token a role with only
the permissions your configuration needs (least privilege).

## Example Usage

```terraform
terraform {
  required_providers {
    fleet = {
      source  = "kforbus3/fleet"
      version = "~> 1.0"
    }
  }
}

provider "fleet" {
  endpoint = "https://fleet.example.com" # or FLEET_URL
  # token  = "flt_..."                   # or FLEET_API_TOKEN (preferred)
}
```

## Schema

### Optional

- `endpoint` (String) Base URL of the Fleet deployment, e.g. `https://fleet.example.com`.
  Falls back to the `FLEET_URL` environment variable.
- `token` (String, Sensitive) Service-account API token (`flt_...`). Falls back to
  the `FLEET_API_TOKEN` environment variable.

## Resources and data sources

| Type | Kind | Notes |
|---|---|---|
| [`fleet_host`](./resources/host.md) | resource | Full CRUD + import. |
| `fleet_group` | resource | Full CRUD; `rule { }` block for dynamic membership. |
| `fleet_service_account` | resource | Create/Delete; any change replaces it. |
| `fleet_service_account_token` | resource | Create/Revoke; secret stored (sensitive) in state. |
| [`fleet_role`](./data-sources/role.md) | data source | Resolve a role name to its UUID. |

> These docs are a scaffold. The full, always-in-sync reference is generated
> from the provider schema with
> [`tfplugindocs`](https://github.com/hashicorp/terraform-plugin-docs):
>
> ```bash
> go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate
> ```
>
> (tfplugindocs is not yet a build dependency of this module; add it before
> running the generator.)
