# High Availability

Fleet Terminal can run as **multiple backend instances** behind a load balancer for
redundancy and rolling upgrades. This guide covers the model, what it guarantees, how
the pieces fit, and how to deploy and operate it.

HA is **safe by default**: a single-instance deployment behaves exactly as before (it
is simply always the leader). Nothing here needs to be turned on to run one instance.

---

## 1. What HA guarantees (and what it doesn't)

**Survives instance loss:** authentication, inventory, all management APIs, the
dashboard, and **starting new** SSH/SFTP/RDP sessions. If an instance dies, the load
balancer routes the next request to a survivor and work continues.

**Does not survive instance loss:** **in-flight interactive sessions on the dead
instance drop and must be reconnected.** A live PTY / SFTP transfer / RDP stream and
its signing key exist only in that instance's RAM — they cannot be migrated. The
browser terminal reconnects and a fresh session starts. This is the standard, honest
HA guarantee for a remote-access product.

State that is already shared (and so survives): login sessions and refresh tokens,
account lockout, the CA (encrypted in Postgres), audit log, all inventory and job
history.

---

## 2. How it works

| Concern | Mechanism |
|---|---|
| **Instance identity** | Each backend generates a fresh UUID at boot and registers a heartbeat row in `cluster_instances`. A restart is a *new* instance (its RAM state is gone). |
| **Leader election** | A Postgres **session-scoped advisory lock**. Whoever holds it is the leader; the lock auto-releases the instant the holder's connection drops (crash, partition, clean stop) → a new leader is elected with no timeout bookkeeping and **no split brain**. |
| **Singleton work** | Cluster-wide jobs run **only on the leader**: host-monitor sweep, KRL distribution, retention pruning, digests, scheduled reports, dynamic-group reconcile, backups, CA-age alerts, and orphan reconciliation. Per-instance work (cert renewal for locally-held sessions, the job scheduler's DB-claimed work) runs on every instance. |
| **Ownership reconciliation** | Long-running rows (sessions, scans, playbook/vuln/remediation/enrollment runs) are tagged with their owning `instance_id`. On boot and periodically, the backend fails only the rows whose owning instance's heartbeat has expired — **never a live peer's work**. |
| **Real-time events** | A **Postgres LISTEN/NOTIFY backplane** bridges the per-instance WebSocket hub, so a host-status or session event raised on any instance reaches dashboard clients connected to every instance. Session terminate is propagated the same way, so an admin can force-close a session whose PTY lives on another instance. |
| **Certificates (issue-own-cert)** | When a request lands on an instance that doesn't hold the session's key, that instance **mints its own** short-lived per-session cert and **never revokes a peer's**. Several concurrently-valid certs per session (one per serving instance) are expected and harmless — each private key lives only in its own instance's RAM. Certs are revoked only on session end, or by a leader sweep once their **issuing instance dies** (they are keyless by then). |
| **Postgres failover** | The pool recycles idle/aged connections (`MaxConnIdleTime` + `MaxConnLifetime`) and reconnects with exponential backoff, so it re-homes onto a promoted primary after a database failover. |

Because any request can be served correctly by any instance (issue-own-cert), **you do
not need sticky sessions / affinity** for correctness. Affinity is only a minor
optimization (fewer per-instance certs).

### Live session shadowing across instances

**Live** shadowing (`Session.Watch` on an *in-progress* session) works from **any**
instance, even when the session's PTY lives on a different one. When a watcher attaches
to a session this instance doesn't own, it announces interest over the backplane; the
owning instance then mirrors that session's live output/resize frames to peers (and
only while a remote watcher is attached, so an unwatched session costs nothing on the
wire). Frames are chunked to fit the NOTIFY payload limit and relayed on a dedicated,
non-blocking path, so shadowing never slows the operator's terminal — under a burst a
remote watcher drops frames rather than stalling the session, exactly as a local slow
watcher does. Post-hoc **replay** likewise works from any instance (recordings live on
shared storage, see §4).

---

## 3. Reference topology

```
                         ┌────────────── clients (browser) ──────────────┐
                         │                                               │
                   ┌─────▼─────┐   TLS / routing edge (your existing NPM)
                   │  Proxy /  │
                   │    LB     │   health-check GET /ready ; WebSockets on
                   └─────┬─────┘   (HAProxy behind NPM recommended — see §6)
              ┌──────────┼──────────┐
        ┌─────▼────┐ ┌───▼─────┐ ┌──▼──────┐
        │ backend1 │ │ backend2│ │ backendN│   stateless; each runs its own guacd-less
        └─────┬────┘ └───┬─────┘ └──┬──────┘   work + shares the DB/storage below
              └──────────┼──────────┘
                 ┌────────▼─────────┐   ┌──────────────────┐   ┌───────────────────┐
                 │  Postgres (HA)   │   │  shared storage  │   │  jump host (+WG)   │
                 │ pooler/Patroni   │   │ recordings,      │   │  VIP + replicated  │
                 │  single URL      │   │ rdp-drive        │   │  WG key (see §5)   │
                 └──────────────────┘   └──────────────────┘   └───────────────────┘
```

- **Backends (2+):** identical config, same `FLEET_DATABASE_URL`, same secrets
  (`FLEET_JWT_SECRET`, `FLEET_CA_PASSPHRASE`, `FLEET_VAULT_PASSPHRASE`, …). Stateless.
- **Postgres:** a single connection URL that points at an HA Postgres (Patroni,
  Cloud SQL/RDS, or a pooler like PgBouncer in front of a primary+replica with
  automatic failover). Size the pool: `FLEET_DB_MAX_CONNS` × number of instances must
  stay within Postgres `max_connections` (leave headroom — each instance also holds
  one connection for the leader lock and one for the event backplane).
- **Shared storage:** see §4.
- **Jump host / WireGuard hub:** see §5.

---

## 4. Shared storage for recordings & file transfer

Session recordings (SSH `.cast` and RDP Guacamole streams) and the RDP redirected-drive
exchange are written to disk. In a multi-instance deployment these directories **must
be on shared storage** (NFS, a clustered filesystem, or an object-store gateway)
mounted at the same path on every backend (and on guacd), because:

- The leader prunes recordings by retention — it must see every instance's files.
- A replay request may be served by any instance — it must be able to read a recording
  written by another.

Point `FLEET_RECORDING_DIR` (default `/var/lib/fleet/recordings`) and
`FLEET_RDP_DRIVE_DIR` (default `/var/lib/fleet/rdp-drive`) at shared mounts. In the
bundled single-host compose these are Docker named volumes (host-local) — replace them
with a shared mount for multi-host HA. guacd must mount the same shared storage as the
backends (it already runs as the backend's `fleet` uid so permissions line up).

---

## 5. Network & jump-host failover (the hard part)

Failover is fundamentally a **network-layer** problem: after a host dies, the survivor
must be reachable at the **same address** clients and managed hosts already trust.

The co-located host in a single-box deployment plays **two roles** — decompose them
for HA:

**(a) Web/control endpoint.** Put the backends behind a **floating VIP** using
keepalived/VRRP (right for a LAN) or a health-checked load balancer. The proxy edge
(NPM) and/or the LB own the VIP; if the active node fails, the VIP moves to the
standby and clients reconnect to the same hostname/IP.

**(b) Jump host + WireGuard hub.** Managed hosts dial **into** the jump host's
WireGuard endpoint, trusting its **endpoint IP:port** and **WG server public key**. A
standby jump host must therefore present:

1. **The same VIP endpoint** (so peers' configured `Endpoint` still resolves). Give the
   jump-host role its own VIP via keepalived.
2. **The same WG server private key** — replicate it to the standby (out of band; treat
   it like the CA key). Peers authenticate the hub by its public key, so the standby
   must own the same keypair.
3. **The peer list**, rebuilt from Postgres. Fleet persists each managed host's WG
   public key + overlay address; on the standby, after restoring the WG key, run:

   ```sh
   # on the standby jump host, bring up wg0 with the replicated private key, then:
   wg addconf wg0 <(fleetctl wg-peers)     # fleetctl reachable to the DB, or pipe the output over
   ```

   `fleetctl wg-peers` emits endpoint-free `[Peer]` stanzas (peers roam and dial in, so
   the hub never needs their `Endpoint`). This reconstructs the overlay without
   re-enrolling a single host.

keepalived can automate step 3 in its `notify_master` script (bring up wg0, apply
`fleetctl wg-peers`). Managed hosts reconnect to the VIP endpoint automatically
(WireGuard roaming).

> The proxy edge itself (NPM) is a single point of failure until it too sits behind a
> VIP with a standby. That is deferrable but should be on the roadmap for true HA.

---

## 6. Load-balancer notes (Nginx Proxy Manager / HAProxy)

- Keep **WebSockets Support** enabled on the proxy host (terminal, SFTP, RDP, and the
  events feed are all WebSockets).
- Health-check **`GET /ready`** (returns ready once the DB is reachable) to eject a
  failed backend.
- Stock NPM cannot do cookie-sticky sessions. **You do not need stickiness** — the
  issue-own-cert model makes every instance able to serve any request. If you want to
  minimize per-instance certs, put **HAProxy behind NPM** (NPM = TLS/routing edge,
  HAProxy = health-checked fan-out with `balance leastconn` and WebSocket passthrough).

---

## 7. Rolling upgrade

Because leadership and reconciliation are lease-based, you can upgrade one instance at
a time with no full outage:

1. Take **backend1** out of the LB rotation (fail its health check or drain it).
   In-flight sessions on backend1 drop; users reconnect (landing on other instances).
2. Stop backend1. On a **clean stop** it unregisters immediately and releases the
   leader lock if it held it; a survivor is elected leader within a heartbeat. Its
   owned sessions are reconciled once its lease expires (~30 s) — or immediately, since
   a clean stop removes its registry row.
3. Deploy the new image for backend1; it runs migrations (idempotent; safe even when
   peers are on the old schema for the additive migrations HA ships), registers a fresh
   identity, and rejoins.
4. Return backend1 to rotation. Repeat for each instance.

Database migrations run on every instance at boot (`FLEET_MIGRATE_ON_START`). The HA
migrations are **additive** (new nullable columns / new tables), so a brief mixed-version
window during a rolling upgrade is safe.

---

## 8. Verifying HA

A ready-made 2-instance test stack ships in `deploy/compose/docker-compose.ha.yml`
(two backends behind a round-robin nginx LB, isolated Compose project — safe to run
alongside a normal stack):

```sh
docker compose --env-file .env -f deploy/compose/docker-compose.ha.yml -p fleet-ha up -d --build
docker compose -p fleet-ha logs -f backend1 backend2 | grep -i cluster   # watch leadership
# API via the LB at http://localhost:8088 ; backends also on :8091 / :8092
docker compose -p fleet-ha down -v                                        # tear down
```

Then exercise:

- **Kill the leader:** stop whichever instance logged `cluster: acquired leadership`.
  Within a heartbeat another logs the same line; singleton jobs (monitor sweep, KRL)
  continue.
- **Kill a session holder:** open a terminal, note which instance serves it, kill that
  instance. The terminal drops; reconnecting opens a new session on a survivor. Confirm
  the dead instance's `ssh_sessions` rows flip to `closed` after its lease expires, and
  that **no live peer's** sessions were touched.
- **Cross-instance events:** connect two dashboards to different instances; a host going
  offline shows on both.
- **Cross-instance terminate:** from an admin on instance A, terminate a user whose
  terminal is on instance B; B closes it.
