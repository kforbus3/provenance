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
- nuclei probes **only the ports known to be listening** (see *Port
  inventory* below). It never sweeps blind

The **jump host is excluded by default**. Its sshd drops connections past
MaxStartups 10 (see the v2.0.11/v2.0.12 scan-drop fixes), and nuclei's SSH
templates would cause those drops. The control-plane host gets a dedicated
opt-in.

### Port inventory: ask the host first, then probe from the network

Two views are merged, and the gap between them is itself a finding:

1. **Inside view (authoritative, every port).** Managed hosts are asked in the
   same SSH/WinRM session the scans already use. On Linux this is `ss -Htulnp`;
   on Windows, `Get-NetTCPConnection -State Listen` plus
   `Get-NetUDPEndpoint`. The answer covers **every** TCP and UDP listener, the
   address it is bound to (`127.0.0.1`, `0.0.0.0` or a specific interface) and
   the owning process. It puts no load on the network, it covers UDP, which
   network scans are poor at, and the process name maps to a package, which is
   what lets Phase 2 correlate with grype.
2. **Outside view (reachability).** naabu does a **full 1–65535 TCP connect
   scan** of every scan path, and nuclei then probes each open port.
   `NETSCAN_RATE` defaults to 1000 pps, which is about 65 s per host per path.
   The full range, not the listener list, is the input on purpose: a port that
   answers but that `ss` did not report is itself a finding (see
   **Unexpected**).
3. **The diff:**
   - **Listening but not reachable anywhere:** the firewall is doing its job.
     Kept as inventory.
   - **Reachable:** in scope for nuclei, tagged with each path that reached it.
   - **Reachable but not in the host's own list:** port forwarding, a NAT rule
     or a lying host. Flagged **Unexpected**.

For unmanaged devices (Phase 3 ranges) only the outside view exists, so the
full TCP scan is the whole inventory.

### Scan paths: both the LAN address and the overlay

Every managed host is scanned on **each path that exists** for it:

- **LAN** (`Host.Address`): what anything on that network sees.
- **Overlay** (`WGAddress`, whether WireGuard or OpenVPN): what the jump host,
  and so anyone who compromises the control plane, can reach. This path is
  **required**, not optional. A roaming or NATed host often has no reachable
  `Address` from the scanner, and without this path those hosts would get no
  coverage at all. It also matters because host firewalls commonly trust `wg0`
  outright.

Each service and finding records `path` (`lan`/`overlay`). Something exposed
**only** on the overlay gets a distinct flag, because it means the host is
trusting the control plane with that service.

To reach the overlay, the sidecar runs with `network_mode: service:jumphost`,
sharing the jump host's network namespace. That namespace is where the tunnel
interfaces live, and strict hub-and-spoke lets the hub reach every peer. The
cost: recreating the jump host means recreating the scanner too.
`make redeploy-single` must handle that, and the sidecar's `/healthz` must fail
when it loses the overlay route so the failure cannot go unnoticed.

Other rules:

- **Unreachable is not clean.** A path where the host does not answer on its
  own SSH or WinRM port is recorded as `unreachable` with a reason. It is
  never recorded as "0 findings". A host is only reported clean when at least
  one path was actually scanned.
- **Network ranges (opt-in, Phase 3):** a `net_scan_targets` list of CIDRs for
  unmanaged devices. Results attach to an IP, and to a host when the IP matches.
- **Federation:** each site's sidecar scans its own LAN and overlay. Results
  come back through the existing ingest.

## Phases

**Phase 1 — sidecar + managed hosts (the core gap).**
1. `deploy/net-scanner/` containing a Dockerfile, `app.py` and tests. Endpoints
   mirror grype-scanner: `/healthz`, `/scan`
   (`{targets, ports}` → `{services[], findings[]}`), `/db/status`,
   `/db/update` and `/db/import` for templates, including an air-gapped
   tarball. The backend collects listeners over SSH/WinRM first and passes each
   path's address to `/scan`.
   It pins the naabu and nuclei versions, which grype-scanner does not do today.
2. Migration `0114_network_findings.sql` adds:
   - `net_scans` (id, tenant, host_id NULL, target, status, reason, started/finished, template_version)
   - `net_listeners` (scan_id, host_id, proto, bind_addr, port, process, pid): the inside view
   - `net_services` (scan_id, ip, path, port, proto, service, product, version, tls, unexpected): the outside view
   - `net_findings` (scan_id, host_id NULL, ip, path, port, template_id, name, severity,
     cve NULL, cvss, matched_at, evidence, remediation)
   - RLS policies plus an entry in `rls_coverage_test.go`
3. `backend/internal/netscan` holds the service, store and handlers. It is
   modelled on `vulnscan`. It carries the tenant context explicitly into the
   worker. **Do not** use `WithoutCancel(context.Background())`: that drops the
   tenant, so RLS returns empty results.
4. A scheduler `Kind: "netscan"` that takes host, group and fleet targets, plus
   a daily template refresh on the same pattern as `vulndb`, with a stale-template
   warning like `staleDBWarning`.
5. UI: a **Network** tab on the host's Vulnerabilities view. It shows each
   listener with its process and bind address, plus LAN and overlay
   reachability badges and the findings. There is also a fleet-wide
   "Exposed services" table that can be filtered to overlay-only and
   Unexpected.

**Phase 2 — correlation with grype (where the value compounds).**
- When a `net_findings.cve` matches a grype `VulnFinding.CVE` on the same host,
  mark both as **network-confirmed** and sort them to the top. That turns
  "5,000 package CVEs" into "these 12 are reachable".
- For grype findings with no nuclei template, attach exposure context. The
  listener's process maps to its package through `dpkg -S` or `rpm -qf` on the
  binary. A grype CVE in a package that owns a **reachable** port outranks the
  same CVE in a library nothing exposes.
- Add network findings to reports, the CycloneDX/VEX export and the Ask
  assistant tools (`tools_compliance.go`).

**Phase 3 — ranges and sites.**
- fingerprintx and the targeted UDP probe set for unmanaged devices (see Decision 1).
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

1. **DECIDED: naabu + nuclei (MIT), plus fingerprintx (Apache-2.0) in Phase 3.**
   How this compares with nmap:
   - **Vulnerability detection: nuclei is better.** Templates verify behaviour.
     nmap's `vulners` maps banners to CVEs and misfires on backported distro
     packages.
   - **TLS/SSH weakness and TCP discovery: about equal.**
   - **Service identification: nmap `-sV` is better.** On managed hosts this does
     not matter, because the host's own listener list names the process and
     package, which is more accurate than a banner. On unmanaged devices it does.
   - **UDP: nmap is better.** Managed hosts are covered by `ss`; unmanaged
     devices are not.

   Phase 3 closes the last two gaps. fingerprintx identifies services on ports
   nuclei cannot place, and a targeted UDP probe set (SNMP including community
   `public`/`private`, NTP mode 6/7, SSDP, TFTP, IPMI) covers the UDP findings
   that matter on network gear. The accepted loss is the long tail of nmap's
   ~12k service signatures. nmap is still excluded on licence grounds, because
   the NPSL restricts redistribution inside a product and `.provup` bundles ship
   the images.
2. Scan **both** the LAN address and the overlay address, tagged by path. *(Revised: the first draft
   scanned only `Address`, which left roaming/NATed hosts with no coverage.)*
3. The port inventory is the host's own listener list plus a full TCP scan.
   *(Revised: the first draft used a fixed top-1000 list.)*
4. Network-range scanning in Phase 3, not Phase 1. **Recommended: Phase 3.**

## Effort

Phase 1 is roughly the size of the container-scan work: a sidecar, one migration,
one package and one UI tab. Phase 2 is a read-time join plus UI badges. Phase 3
is mostly UI, API and federation plumbing.
