---
page_title: "prov_host Resource - fleet"
description: |-
  A host managed (enrolled) in Provenance.
---

# prov_host (Resource)

Enrolls and manages a host in Provenance. Supports full CRUD and
`terraform import <host-id>`.

## Example Usage

```terraform
resource "prov_host" "web" {
  hostname    = "web-01"
  environment = "production"
  owner       = "platform"
  ssh_user    = "fleet"
  tags        = ["web", "prod"]
}
```

## Schema

### Required

- `hostname` (String) The host's name/address.

### Optional

- `environment` (String) Environment label (e.g. `production`).
- `owner` (String) Owning team or person.
- `ssh_user` (String) Default SSH login user Provenance brokers as.
- `tags` (List of String) Free-form tags; used by dynamic-group rules.

### Read-Only

- `id` (String) The host UUID assigned by Provenance.

## Import

```shell
terraform import prov_host.web <host-id>
```

> This page is a scaffold; regenerate the authoritative schema with
> `tfplugindocs generate` (see the provider index).
