# Logs

Provenance searches the [Aldgate](https://github.com/kforbus3/aldgate) log
collector, so the fleet's logs are in the same place as the fleet.

## What it is

Aldgate receives syslog from every host and SNMP traps from network devices,
stores them in OpenSearch, and serves OpenSearch Dashboards. Provenance adds the
two things a shared log store otherwise lacks: **one identity** and **a record
of who searched what**.

## Deploying a collector

About ten minutes, and it is a separate machine on purpose: a log store that dies
with the thing it was recording is not a log store.

**1. Stand up the collector.** Any Debian/Ubuntu box with Docker — 4 GB RAM is
enough for a small fleet.

```bash
git clone https://github.com/kforbus3/aldgate && cd aldgate
make up          # random admin password, index templates, retention, dashboards
make health      # nothing is sending yet; this proves it is listening
```

**2. Point Provenance at it.** Four values from the collector's `.env` into
Provenance's, then `make redeploy-single`:

```ini
PROV_ALDGATE_URL=http://<collector>:9200
PROV_ALDGATE_USER=admin
PROV_ALDGATE_PASSWORD=<ALDGATE_ADMIN_PASSWORD>
ALDGATE_HOST=<collector>:5601
PROV_ALDGATE_CONSOLE_VIEWER_PASSWORD=<ALDGATE_CONSOLE_VIEWER_PASSWORD>
PROV_ALDGATE_CONSOLE_ADMIN_PASSWORD=<ALDGATE_CONSOLE_ADMIN_PASSWORD>
```

On the collector, set `ALDGATE_BASEPATH=/aldgate`,
`ALDGATE_REWRITE_BASEPATH=true`, and — when Provenance is on another machine —
`ALDGATE_API_BIND=0.0.0.0`; then `make up` again.

**3. Make hosts send.** From **Automation → Playbooks**, paste
`ansible/enroll-syslog.yml` from the Aldgate repo and run it against every Linux
host. One run does the fleet: it installs rsyslog where a host has only journald,
turns on `ForwardToSyslog`, writes a disk-queued forwarding rule, and filters out
Provenance's own probe churn (which is otherwise 90% of the traffic).

Container logs are separate — `ansible/enroll-docker-logs.yml` sets the Docker
daemon's log driver.

**4. Make network devices send.** They refuse key auth, so their credentials live
in Provenance's vault and these run from the same Playbooks page:
`ansible/enroll-routeros.yml` for MikroTik (syslog **and** SNMP traps) and
`ansible/enroll-openwrt.yml` for OpenWrt. SwOS switches can do neither; there is
nothing to enrol.

**5. Check it.** `make health` on the collector, then the **Logs** page here. The
host filter lists everything that has sent anything, so a host missing from it has
not sent — which is a different problem from a search that matched nothing.

### When something is missing

| Symptom | Cause |
|---|---|
| A host is absent from the last hour but present over 24h | its clock or timezone. RFC3164 syslog carries no offset, so a host in a non-UTC zone lands hours in the past — the enrolment playbook forwards RFC5424, network gear needs `ALDGATE_TIMEZONE` |
| The console asks for a username and password | the two `PROV_ALDGATE_CONSOLE_*` values have not reached Provenance |
| The console opens but has no index patterns | saved objects went to a private tenant. `make bootstrap` on the collector writes them to the shared one |
| The Logs page says no collector is configured | `PROV_ALDGATE_URL` is empty |

## Two surfaces

**Logs** (the page) answers the question an operator actually arrives with —
*what was this machine saying, around then*. Search text, filter by host,
severity and time range, and see which hosts and severities the match is spread
across so you can narrow from "something is wrong" to "it is that machine". The
host filter is typeable — three characters and Enter, rather than hunting a menu
that grows with the fleet.

**Open log console** opens Dashboards, proxied under Provenance's own origin at
`/aldgate/`, for what a table should not try to be: visualisations, Alerting,
and Security Analytics detection rules.

## How it is wired

    browser ──► Provenance ──► OpenSearch (10.10.0.177:9200)
                     │
                     └──► /aldgate/ ──► Dashboards (10.10.0.177:5601)

Searches go through a broker in the backend, never from the browser. That is
what keeps the collector's credential server-side, and it is what makes the
audit record real: every search is written as `logs.search` with the query, the
host and severity filters, the time range, and how many documents matched.

`Logs.View` gates all of it. It is seeded to Super Administrator,
Administrator, Operator and Auditor — anyone who can already open a shell on a
host can read its logs there, so withholding the collected copy would protect
nothing and only make the collector less useful. There is deliberately **no**
write permission: changing a log is not something an audit trail should offer,
and retention is the collector's business.

## Configuration

| Variable | Meaning |
|---|---|
| `PROV_ALDGATE_URL` | The collector's OpenSearch API, e.g. `http://10.10.0.177:9200`. **Empty disables the Logs page**, which is the case for any deployment without a collector — the page then says how to point at one rather than reporting a fault. |
| `PROV_ALDGATE_USER` | Defaults to `admin`. |
| `PROV_ALDGATE_PASSWORD` | From the collector's `.env`. |
| `ALDGATE_HOST` | `host:port` of Dashboards, for the `/aldgate/` proxy. Defaults to a nonexistent name so a deployment without a collector gets a 502 on that one path instead of an nginx that will not start. |
| `PROV_ALDGATE_CONSOLE_VIEWER_USER` / `..._PASSWORD` | The read-only console account (default user `prov_viewer`). From the collector's `.env`, where `make bootstrap` generates it. |
| `PROV_ALDGATE_CONSOLE_ADMIN_USER` / `..._PASSWORD` | The full console account (default user `prov_admin`), same source. |

The collector must serve Dashboards under the sub-path: set
`ALDGATE_BASEPATH=/aldgate` and `ALDGATE_REWRITE_BASEPATH=true` in Aldgate's
`.env`. Provenance's nginx then forwards the `/aldgate/` prefix **intact** —
Dashboards strips it itself, and stripping it in nginx as well makes every
request a 404 while the proxy looks correct.

The collector also needs `ALDGATE_API_BIND=0.0.0.0` when Provenance runs on a
different machine, which it does here — the broker cannot reach a loopback port
on another host. The security plugin stays on either way, so the credential is
what protects 9200.

## Opening the console

**Open log console** signs you in. It used to hand you to Dashboards' own login
form, which meant the only credential that worked was the collector's `admin`
account — every privilege there is — and your Provenance role had no bearing on
what you could do once past it. The collector had no idea who you were either.

Now Provenance mints a short-lived console session, scoped to `/api/v1/logs` and
held in an HttpOnly cookie on `/aldgate`. nginx checks that cookie on every
request to the console through `auth_request`, and the backend answers with the
collector credential for the tier your permissions earn:

| Permission | Console |
|---|---|
| `Logs.View` | Read-only. Search, visualise, build dashboards; Dashboards itself runs in read-only mode and the account can read only `syslog-*` and `snmp-*`. |
| `Logs.Administer` | Everything: index management, retention policies, the collector's own settings. Seeded to Super Administrator and Administrator only. |

Two properties worth knowing:

- **The credential never reaches the browser.** It travels in a response header
  from an `internal` nginx location, which nginx copies into the proxied request.
  Nothing in a page, a body or a cookie carries it.
- **The tier is decided per request, not at sign-in.** A console session lasts
  twelve hours; a role change must not. Someone moved from Administrator to
  Operator drops to the read-only tier on their next request, with no cookie to
  hunt down.

Opening the console is audited as `logs.console.open` with the tier, and signing
out of Provenance revokes the session, so the next person at that browser does not
inherit a working console.

If the console asks for a password, the collector's credentials have not reached
Provenance: run `make bootstrap` on the collector and copy
`ALDGATE_CONSOLE_VIEWER_PASSWORD` / `ALDGATE_CONSOLE_ADMIN_PASSWORD` from its
`.env` into Provenance's `PROV_ALDGATE_CONSOLE_*` variables.

## Enrolling hosts

From Aldgate's repo, via **Automation → Playbooks** or directly:

    ansible-playbook -i <inventory> ansible/enroll-syslog.yml -e aldgate_host=10.10.0.177

It installs rsyslog where a host has only journald — every cloud-image VM does —
enables `ForwardToSyslog`, and writes a disk-queued forwarding rule so a
collector outage does not become a hole in that host's history. Container logs
are separate; see `enroll-docker-logs.yml`.

It also forces **RFC5424** on the forwarding rule. rsyslog's default, RFC3164,
sends `Sep 18 16:32:25` with no timezone, so the collector reads it as UTC and
files a host running in EDT four hours in the past. Nothing errors; the host
simply vanishes from every time-based search, which reads exactly like a machine
that stopped sending. If you enrol a host by hand, forward RFC5424.

## Fields

Every message is normalised, which is what makes it searchable rather than
greppable: `host` and `host_short`, `program`, `severity` with a numeric
`severity_code` (so "error or worse" is a range), `facility`, `message`, and
both `timestamp` (what the sender claimed) and `received_at` (when it arrived) —
they differ when a device's clock is wrong — or when it is sending RFC3164 and
Aldgate's `ALDGATE_TIMEZONE` is not set to the LAN's offset.

SNMP traps carry the same fields and are searched together with syslog, because
a switch's trap and the kernel message from the host behind it are usually the
same incident seen twice — a page that showed one without the other would
quietly report a healthy network. `log_type` tells them apart (`syslog` or
`snmp_trap`) when you want only one.
