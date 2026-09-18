# Logs

Provenance searches the [Aldgate](https://github.com/kforbus3/aldgate) log
collector, so the fleet's logs are in the same place as the fleet.

## What it is

Aldgate receives syslog from every host and SNMP traps from network devices,
stores them in OpenSearch, and serves OpenSearch Dashboards. Provenance adds the
two things a shared log store otherwise lacks: **one identity** and **a record
of who searched what**.

## Two surfaces

**Logs** (the page) answers the question an operator actually arrives with —
*what was this machine saying, around then*. Search text, filter by host,
severity and time range, and see which hosts and severities the match is spread
across so you can narrow from "something is wrong" to "it is that machine".

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

The collector must serve Dashboards under the sub-path, or the embed is a blank
page with no error anywhere: set `ALDGATE_BASEPATH=/aldgate` and
`ALDGATE_REWRITE_BASEPATH=true` in Aldgate's `.env`.

The collector also needs `ALDGATE_API_BIND=0.0.0.0` when Provenance runs on a
different machine, which it does here — the broker cannot reach a loopback port
on another host. The security plugin stays on either way, so the credential is
what protects 9200.

## Enrolling hosts

From Aldgate's repo, via **Automation → Playbooks** or directly:

    ansible-playbook -i <inventory> ansible/enroll-syslog.yml -e aldgate_host=10.10.0.177

It installs rsyslog where a host has only journald — every cloud-image VM does —
enables `ForwardToSyslog`, and writes a disk-queued forwarding rule so a
collector outage does not become a hole in that host's history. Container logs
are separate; see `enroll-docker-logs.yml`.

## Fields

Every message is normalised, which is what makes it searchable rather than
greppable: `host` and `host_short`, `program`, `severity` with a numeric
`severity_code` (so "error or worse" is a range), `facility`, `message`, and
both `timestamp` (what the sender claimed) and `received_at` (when it arrived) —
they differ when a device's clock is wrong.
