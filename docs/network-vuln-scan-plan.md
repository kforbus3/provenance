# Network Vulnerability Scanning (the "Nessus gap") — Plan

Status: proposed. Adds a network-side scan next to the existing grype scans. It
does not replace them.

Provenance's CVE coverage today comes from **inside** each host: package databases
go to grype over SSH, and installed Windows apps go over WinRM to CPE and grype.
That answers "what is installed and vulnerable". It cannot answer the questions a
Nessus-style scan answers from **outside**, on the network:

## Problem

| Gap | Example | Why grype cannot see it |
|---|---|---|
| Exposed vulnerable services | An old Jenkins or a Grafana path-traversal answering on a port | Only package-manager software is inventoried; a container, `/opt` tarball or static binary is invisible |
| Weak protocol config | TLS 1.0, weak ciphers, SSH CBC/`diffie-hellman-group1`, expired certs | These are configuration, not package versions |
| Default or no auth | Redis, MongoDB or Elasticsearch with no auth; admin panels on default creds | Configuration and exposure, not a CVE on a package |
| Devices Provenance cannot log into | Switches, printers, IoT, the OpenWrt gateway | No SSH or package DB. `collectScript` reports "no package DB", which is correct but empty |
| Exposure context for existing findings | Is the OpenSSL CVE grype found on a port anyone can reach? | grype has no view of the network |

## Recommended approach

A **`net-scanner` sidecar** built the same way as `grype-scanner`: a small Python
API, an unprivileged user, a template DB fetched at runtime (online update or
offline import) and a bounded concurrency setting. Tools:

- **naabu** (ProjectDiscovery, MIT) for port discovery, in TCP connect mode so
  it needs no raw sockets or `NET_RAW`.
- **nuclei** (ProjectDiscovery, MIT) for service fingerprinting and vulnerability
  checks, using the community templates. Those include CVE checks, default-login
  checks, exposure and misconfiguration checks, plus the `ssl` and `network`
  protocol templates for TLS and SSH weaknesses.

Why these two instead of nmap: both are MIT, like everything else in
`THIRD-PARTY-LICENSES.md`. nmap's NPSL restricts redistribution inside a shipped
product. nmap `-sV` fingerprints services better, so it stays a drop-in option
if the licence question is ever settled.

### Template policy (safety)

Nessus-style scanning has to be **safe by default**. Every scan runs with:

- `-exclude-tags dos,fuzz,intrusive,brute-force` and `-severity low,medium,high,critical`
  (info-level fingerprints are stored as services, not findings)
- `-rate-limit` and `-concurrency` taken from env, with low defaults
  (`NETSCAN_RATE=50`, `NETSCAN_CONCURRENCY=10`)
- a fixed port set (`NETSCAN_PORTS`, default top-1000 plus common admin ports)
  rather than all 65k ports

The **jump host is excluded by default**. Its sshd drops connections past
MaxStartups 10 (see the v2.0.11/v2.0.12 scan-drop fixes), and nuclei's SSH
templates would cause those drops. The control-plane host gets a dedicated
opt-in.

### Targets and reach

- **Managed hosts:** scan `Host.Address`. That is the attacker's view of the
  host, which is the point of the scan. It is **not** the overlay address:
  scanning `WGAddress` only tests what the jump host can reach, which is a
  different question.
- **Unreachable is not clean.** This is the same lesson as `noPackageDBMarker`.
  If naabu finds no open ports **and** the host does not answer TCP on its own
  SSH or WinRM port, the scan records `unreachable` with a reason. It never
  records "0 findings".
- **Network ranges (opt-in):** a new `net_scan_targets` list of CIDRs for devices
  that are not managed, such as switches, printers and the gateway. Results
  attach to an IP, and to a host when the IP matches a `Host.Address`.
- **Federation:** each site runs its own sidecar and scans its own networks, so
  the hub never needs a route into a site's LAN. Results come back through the
  existing federation ingest.

## Phases

**Phase 1 — sidecar + managed hosts (the core gap).**
1. `deploy/net-scanner/` containing a Dockerfile, `app.py` and tests. Endpoints
   mirror grype-scanner: `/healthz`, `/scan`
   (`{targets, ports}` → `{services[], findings[]}`), `/db/status`,
   `/db/update` and `/db/import` for templates, including an air-gapped tarball.
   It pins the naabu and nuclei versions, which grype-scanner does not do today.
2. Migration `0114_network_findings.sql` adds:
   - `net_scans` (id, tenant, host_id NULL, target, status, reason, started/finished, template_version)
   - `net_services` (scan_id, ip, port, proto, service, product, version, tls)
   - `net_findings` (scan_id, host_id NULL, ip, port, template_id, name, severity,
     cve NULL, cvss, matched_at, evidence, remediation)
   - RLS policies plus an entry in `rls_coverage_test.go`
3. `backend/internal/netscan` holds the service, store and handlers. It is
   modelled on `vulnscan`. It carries the tenant context explicitly into the
   worker. **Do not** use `WithoutCancel(context.Background())`: that drops the
   tenant, so RLS returns empty results.
4. A scheduler `Kind: "netscan"` that takes host, group and fleet targets, plus
   a daily template refresh on the same pattern as `vulndb`, with a stale-template
   warning like `staleDBWarning`.
5. UI: a **Network** tab on the host's Vulnerabilities view listing open
   services and findings, plus a fleet-wide "Exposed services" table.

**Phase 2 — correlation with grype (where the value compounds).**
- When a `net_findings.cve` matches a grype `VulnFinding.CVE` on the same host,
  mark both as **network-confirmed** and sort them to the top. That turns
  "5,000 package CVEs" into "these 12 are reachable".
- For grype findings with no nuclei template, attach exposure context: the
  package (for example `openssh-server` or `nginx`) owns a listening service
  that `net_services` saw open.
- Add network findings to reports, the CycloneDX/VEX export and the Ask
  assistant tools (`tools_compliance.go`).

**Phase 3 — ranges and sites.**
- The CIDR target UI and API, plus the Terraform provider resource.
- A federation site sidecar and ingest.
- A "new service appeared" notification, using the diff between scans. This is
  cheap and is often the most useful alert of all.

## Accuracy and limits (state plainly)

- nuclei templates cover **known, high-signal** issues. This is not Nessus's
  ~200k plugins. Nessus has broader coverage, especially of Windows/SMB internals
  and vendor appliances; this plan fills the common, high-value part of the gap.
- It is unauthenticated: no login-based checks. That is deliberate, because
  grype already does the authenticated side better than Nessus's local checks.
- Version-banner CVE matches can be false positives on distros that backport
  fixes. Where grype has the host's real package version, grype's verdict
  **wins** and the network finding is marked "banner-only".

## Rollout (verify one before all)

1. `testfabric`: add a deliberately weak target, such as Redis with no auth and
   nginx with TLS 1.0. Tests must assert those findings **appear**. A clean
   host returning zero findings proves nothing.
2. Prod: scan **one** managed host by hand and compare against a manual
   `nuclei`/`nmap` run.
3. Then schedule a single group, then the whole fleet, with the jump host still
   excluded.

## Decisions (to confirm)

1. naabu + nuclei (MIT) rather than nmap (NPSL). **Recommended: naabu + nuclei.**
2. Scan `Address` rather than the overlay. **Recommended: `Address`.**
3. Network-range scanning in Phase 3, not Phase 1. **Recommended: Phase 3**,
   because managed hosts are where findings can be acted on.

## Effort

Phase 1 is roughly the size of the container-scan work: a sidecar, one migration,
one package and one UI tab. Phase 2 is a read-time join plus UI badges. Phase 3
is mostly UI, API and federation plumbing.
