---
page_title: "fleet_role Data Source - fleet"
description: |-
  Resolve a Fleet role name to its UUID.
---

# fleet_role (Data Source)

Looks up a role by name and returns its UUID, for use in `role_ids` on service
accounts. The Fleet API returns role *names* rather than IDs on read, so this
data source is the bridge from a human-readable name to the ID configurations need.

## Example Usage

```terraform
data "fleet_role" "operator" {
  name = "Operator"
}

resource "fleet_service_account" "ci" {
  username = "ci"
  role_ids = [data.fleet_role.operator.id]
}
```

## Schema

### Required

- `name` (String) The role's display name (exact match).

### Read-Only

- `id` (String) The role UUID.

> This page is a scaffold; regenerate the authoritative schema with
> `tfplugindocs generate` (see the provider index).
