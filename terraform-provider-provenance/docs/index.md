---
page_title: "Provenance Provider"
description: |-
  Manage a Provenance deployment (hosts, groups, service accounts, tokens)
  as infrastructure-as-code.
---

# Provenance Provider

The Provenance provider manages a [Provenance](https://github.com/kforbus3/Provenance-Terminal)
Privileged Access Management deployment as code: hosts, groups (including dynamic
membership rules), service accounts, and their API tokens.

It authenticates with a **service-account API token** (`flt_…`), issued from
**Settings → Service Accounts** in the Provenance UI. Grant the token a role with only
the permissions your configuration needs (least privilege).

## Example Usage

```terraform
terraform {
  required_providers {
    fleet = {
      source  = "kforbus3/provenance"
      version = "~> 1.0"
    }
  }
}

provider "fleet" {
  endpoint = "https://provenance.example.com" # or PROV_URL
  # token  = "flt_..."                   # or PROV_API_TOKEN (preferred)
}
```

## Schema

### Optional

- `endpoint` (String) Base URL of the Provenance deployment, e.g. `https://provenance.example.com`.
  Falls back to the `PROV_URL` environment variable.
- `token` (String, Sensitive) Service-account API token (`flt_...`). Falls back to
  the `PROV_API_TOKEN` environment variable.

## Resources and data sources

| Type | Kind | Notes |
|---|---|---|
| [`prov_host`](./resources/host.md) | resource | Full CRUD + import. |
| `prov_group` | resource | Full CRUD; `rule { }` block for dynamic membership. |
| `prov_service_account` | resource | Create/Delete; any change replaces it. |
| `prov_service_account_token` | resource | Create/Revoke; secret stored (sensitive) in state. |
| [`prov_role`](./data-sources/role.md) | data source | Resolve a role name to its UUID. |

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
