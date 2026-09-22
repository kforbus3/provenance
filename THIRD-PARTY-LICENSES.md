# Third-party software

Provenance is distributed under the Apache License 2.0 (see `LICENSE`). It
includes and depends on third-party software under its own licences, listed here.

Counts were produced with `go-licenses` (backend) and `license-checker --production`
(frontend) against the versions in `backend/go.mod` and `frontend/package-lock.json`.
Regenerate them when dependencies change — the commands are at the bottom.

## Written offer for source code (GPL components)

**Ansible** and its Galaxy collections are licensed **GPL-3.0-or-later** and are
installed into the `provenance-ansible-runner` container image, which ships inside
every `.provup` upgrade bundle. Provenance therefore distributes Ansible in binary
form.

For a period of three years from the date you received a Provenance release, the
Licensor will provide, on request and for no more than the cost of physically
performing the distribution, a complete machine-readable copy of the corresponding
source code for the GPL-licensed components it distributes. Requests may be sent to
the address in `SECURITY.md`. The same source is also available from the upstream
projects:

- Ansible — https://github.com/ansible/ansible
- Ansible Galaxy collections (`community.routeros`, `ansible.netcommon`) — https://galaxy.ansible.com

Ansible runs as a separate process in a separate container, invoked over HTTP. It is
not linked into any Provenance binary, and no Provenance source is derived from it.

**OpenVPN** (GPL-2.0) and **WireGuard tools** (GPL-2.0) are *not* distributed by
Provenance. The jump-host image is built on the operator's own machine from a
Dockerfile that installs them from the distribution's package repositories, and
managed hosts install them through their own package manager or `winget`. What
Provenance distributes is the build recipe and the configuration, not the binaries.

**Base-image packages.** The container images Provenance builds are based on Debian,
Ubuntu and Alpine images, which contain GPL-licensed system packages (coreutils, bash,
and similar). Source for these is published by each distribution:
Debian https://sources.debian.org, Ubuntu https://packages.ubuntu.com,
Alpine https://gitlab.alpinelinux.org/alpine/aports.

## Mozilla Public License 2.0 components

MPL-2.0 is file-level copyleft: if a covered file is modified, the modified file's
source must be made available. Provenance uses all four unmodified.

- `github.com/go-sql-driver/mysql`
- `github.com/hashicorp/go-cleanhttp`
- `github.com/hashicorp/go-uuid`
- `github.com/hashicorp/yamux`

## Backend (Go) — `provd`, `provctl`, `prov-updater`

No GPL, LGPL or AGPL code is compiled into any Provenance binary.

| Licence | Packages |
|---|---|
| Apache-2.0 | 40 |
| MIT | 26 |
| BSD-3-Clause | 22 |
| BSD-2-Clause | 4 |
| MPL-2.0 | 4 (listed above) |
| ISC | 1 |

## Frontend (npm, production dependencies)

| Licence | Packages |
|---|---|
| MIT | 237 |
| ISC | 4 |
| BSD-3-Clause | 3 |
| OFL-1.1 | 1 — `@fontsource/roboto` (Open Font License; redistribution permitted with attribution) |

`guacamole-common-js` is part of the Apache Guacamole project and is licensed
**Apache-2.0**; its npm metadata reports the licence only as "BSD*", which is why it is
called out rather than counted above.

## Container images pulled at deploy time

These are referenced by the compose files and pulled from their own registries. They
are not redistributed by Provenance.

| Image | Licence |
|---|---|
| `postgres:16-alpine` | PostgreSQL License |
| `guacamole/guacd:1.5.5` | Apache-2.0 |
| `ghcr.io/headlamp-k8s/headlamp` | Apache-2.0 |

## Vulnerability tooling

`grype` and `syft` (Anchore) are Apache-2.0. Vulnerability data is fetched from the
providers' own feeds at runtime and is subject to their terms — notably the NVD and
the Microsoft Security Response Center.

## Regenerating these lists

```sh
# backend
cd backend && go-licenses report ./cmd/provd | awk -F, '{print $3}' | sort | uniq -c

# frontend
cd frontend && npx license-checker --production --summary
```
