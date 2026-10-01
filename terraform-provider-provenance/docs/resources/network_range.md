---
page_title: "prov_network_range Resource - provenance"
description: |-
  A network range the network scanner sweeps for devices that are not managed hosts.
---

# prov_network_range (Resource)

A network range scanned for devices Provenance does not manage — switches, printers,
appliances, the gateway. Live addresses are found with the common ports, then each is
scanned in full (every TCP port, service identification, vulnerability and
misconfiguration checks). Requires `System.Configure`. Supports
`terraform import <range-id>`.

## Example Usage

```terraform
resource "prov_network_range" "lab" {
  name = "lab LAN"
  cidr = "10.0.2.0/24"
  note = "switches, printers, IoT"
}
```

## Schema

### Required

- `name` (String) Display name.
- `cidr` (String) The network in canonical CIDR form, e.g. `10.0.2.0/24` (not
  `10.0.2.5/24`, which plan rejects because the API stores the network address). At
  most 1024 addresses; loopback, link-local and multicast are refused.

### Optional

- `note` (String) Free-text note.
- `enabled` (Boolean) Included in scheduled range scans. Default `true`.

### Read-Only

- `id` (String) The range ID.
