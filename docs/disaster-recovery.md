# Fleet Terminal — Disaster Recovery

This guide covers the **DR planning** side of Fleet Terminal: recovery objectives
(RPO/RTO), what state must be protected, and the failure scenarios you should
rehearse for. The platform's durable state lives in **PostgreSQL** and the
**session recordings directory**; the CA private key (encrypted) lives in the
database, protected by `FLEET_CA_PASSPHRASE`.

> **The encrypted-backup and rebuild procedure lives in
> [break-glass.md](./break-glass.md) — that runbook is authoritative.** Fleet's
> shipped backups are produced under **Settings → Backup & Restore**: `pg_dump`
> piped through `openssl` (AES-256-CBC, PBKDF2) into `FLEET_BACKUP_DIR`
> (default `/var/lib/fleet/backups`), with optional scheduling + retention.
> This document does **not** repeat those steps; it covers what to protect and
> the recovery scenarios around them.

## What must be protected

| Asset | Where | Notes |
|-------|-------|-------|
| Relational state | PostgreSQL (`pgdata` volume) | users, RBAC, hosts, certs, sessions, audit, settings — captured by the encrypted backup |
| CA private key | `ca_keys.private_enc` in PostgreSQL | encrypted with `FLEET_CA_PASSPHRASE`; rides along inside the DB backup (still ciphertext) |
| Encrypted backups | `backups` volume (`FLEET_BACKUP_DIR`, default `/var/lib/fleet/backups`) | `pg_dump` + `openssl` AES-256 files; **get them off the host** |
| `FLEET_CA_PASSPHRASE` | password manager / sealed offline copy | **without it the CA key is unrecoverable**; deliberately **not** in any backup |
| `FLEET_BACKUP_PASSPHRASE` | password manager / sealed offline copy | decrypts the backups; falls back to `FLEET_CA_PASSPHRASE`; deliberately **not** in any backup |
| `FLEET_JWT_SECRET`, `FLEET_CSRF_SECRET` | secret store / `.env` | losing these invalidates live tokens (users re-login) |
| Jump host volumes | `jump_wg`, `jump_ssh` Docker volumes | WireGuard peers + SSH host key; recoverable by re-enrolling hosts, but tedious |
| Session recordings | `recordings` volume (`FLEET_RECORDING_DIR`) | asciicast files referenced by `session_recordings.path` |
| Audit export | external archive | immutable copy of the hash chain |

> **Critical:** keep `FLEET_CA_PASSPHRASE` and `FLEET_BACKUP_PASSPHRASE` **off the
> server** — a copy in a password manager (or a sealed envelope). They are
> deliberately excluded from backups, so a stolen backup can't be decrypted, but
> that also means a backup is useless for recovery without them. Losing
> `FLEET_CA_PASSPHRASE` means rotating to a brand-new CA and re-trusting it on
> every managed host.

## Backups (where DR fits)

Fleet's **database backup is the encrypted `pg_dump | openssl` artifact** managed
under **Settings → Backup & Restore** and documented step-by-step in
[break-glass.md](./break-glass.md): enable scheduling + retention, get the files
**off the host** (map `FLEET_BACKUP_DIR` to off-host storage or rsync the
directory elsewhere), and rehearse the decrypt/restore. Do **not** treat an ad-hoc
plain `pg_dump` as your backup path — it omits encryption, scheduling, and
retention.

The database backup captures **everything in PostgreSQL**, including the encrypted
CA key, RBAC, hosts, and the audit chain. The pieces it does **not** cover, and
that DR planning must account for separately:

- **Session recordings** — on the `recordings` volume (`FLEET_RECORDING_DIR`), not
  in the database. Snapshot the volume alongside the DB backup:
  ```sh
  docker run --rm -v compose_recordings:/data -v "$PWD/backups:/backup" alpine \
    tar czf /backup/recordings-$(date +%Y%m%d).tar.gz -C /data .
  ```
  (Volume name is `compose_recordings` under the default Compose project; confirm
  with `docker volume ls`.)
- **Jump host volumes** — `jump_wg` (WireGuard keypair + peers) and `jump_ssh`
  (SSH host key). Recoverable by re-enrolling every host, but snapshotting these
  avoids that churn after a jump-host rebuild.
- **Audit chain export** — independently archive the tamper-evident chain to
  immutable/write-once storage for an out-of-band copy:
  ```sh
  curl -s "http://localhost:8080/api/v1/audit/export" \
    -H "Authorization: Bearer $TOKEN" \
    -o backups/audit-$(date +%Y%m%d).json
  ```
- **Secrets** — keep `FLEET_JWT_SECRET`, `FLEET_CSRF_SECRET`,
  `FLEET_CA_PASSPHRASE`, and `FLEET_BACKUP_PASSPHRASE` in your secret manager (or
  `deploy/k8s/11-secret.yaml`), with sealed offline copies of the two passphrases.
  Redis (`redisdata`) is a cache/job broker and does not need backup.

## Restore (full)

The end-to-end **rebuild-from-backup** procedure — decrypting the backup with
`openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:"$FLEET_BACKUP_PASSPHRASE"` and
piping into `psql "$FLEET_DATABASE_URL"`, then restarting the backend — is in
[break-glass.md](./break-glass.md). DR-specific notes that complete that flow:

1. Bring the stack up with the **same `.env`** — crucially the same
   `FLEET_CA_PASSPHRASE`, `FLEET_BACKUP_PASSPHRASE`, `FLEET_JWT_SECRET`, and
   `FLEET_CSRF_SECRET` as the original deployment.
2. After restoring the database, restore the **recordings volume** (reverse of the
   tar above) and, if the jump host was lost, the **`jump_wg` / `jump_ssh`**
   volumes.
3. **Verify** (see below).

On startup the backend runs migrations idempotently (`FLEET_MIGRATE_ON_START`)
and `EnsureUserCA` finds the existing CA — it will **not** create a new one, so
managed hosts continue to trust it.

## Verification after restore

```sh
curl -s http://localhost:8080/ready                              # {"status":"ready"}
curl -s http://localhost:8080/api/v1/audit/verify -H "Authorization: Bearer $TOKEN"
# expect {"intact": true, "brokenAtSeq": 0}
curl -s http://localhost:8080/api/v1/certificates/ca -H "Authorization: Bearer $TOKEN"
# confirm activeUserCA matches what managed hosts trust
```

Then have a user open a terminal to confirm end-to-end SSH works.

## Recovery scenarios

### Lost all administrators / locked out

The bootstrap wizard self-closes once any user exists. To recover:

1. Confirm there is genuinely no usable admin (`SELECT username, is_super_admin,
   is_disabled, locked_until FROM users;`).
2. **Preferred — unlock/reset in place** (direct DB access): clear a lockout or
   reset a known admin, e.g.
   ```sql
   UPDATE users SET is_disabled=false, locked_until=NULL, failed_logins=0
   WHERE username='admin';
   ```
   Re-issue the password hash via the app's reset flow if you still have any
   account that holds `User.ResetPassword`.
3. **Reopen bootstrap (offline recovery):** with the app stopped, delete the
   remaining (orphaned) user rows so the user count reaches zero, set
   `FLEET_ALLOW_BOOTSTRAP=true`, restart, and re-run the wizard. This is a
   break-glass procedure — perform it deliberately and audit it. Re-disable
   bootstrap (`FLEET_ALLOW_BOOTSTRAP=false`) afterward.

### CA key compromise

1. Rotate the CA: `POST /api/v1/certificates/ca/rotate`.
2. Distribute the new `activeUserCA` public key to every managed host's
   `TrustedUserCAKeys`.
3. Revoke outstanding certificates if needed and publish the KRL
   (`GET /api/v1/certificates/krl`) to hosts' `RevokedKeys`.
See [certificate-lifecycle.md](./certificate-lifecycle.md).

### Lost `FLEET_CA_PASSPHRASE`

The stored CA private key cannot be decrypted. You must generate a **new** CA
(rotate) and re-trust its public key on all hosts. Existing certificates signed by
the old CA can no longer be renewed; sessions will need re-issuance under the new
CA.

### Lost `FLEET_JWT_SECRET` / `FLEET_CSRF_SECRET`

Live access tokens and CSRF cookies become invalid; users simply log in again. Set
fresh strong secrets and restart.

### Suspected audit tampering

`GET /api/v1/audit/verify` returns `intact: false` with the first broken `seq`.
Compare against your immutable audit exports to determine what was altered, treat
as a security incident, and preserve evidence (DB snapshot + exports).

## RPO / RTO planning

- **RPO** is bounded by your DB backup + audit-export frequency (e.g. daily dumps
  + continuous WAL archiving for near-zero RPO).
- **RTO** is dominated by DB restore time and re-distributing the CA public key
  only if the CA had to be regenerated.
- Rehearse restores quarterly and after any schema migration. The whole stack is
  reproducible via `make up` / `make up-app`, so DR drills are cheap.

## Backup & Restore (operational)

**Backup** — Admins manage encrypted backups under **Settings → Backup & Restore**:
"Back up now", scheduled backups with a retention count, and download. Each file is
`pg_dump` piped through `openssl` (AES-256-CBC, PBKDF2) into `FLEET_BACKUP_DIR`
(default `/var/lib/fleet/backups`, the `backups` volume). See
[break-glass.md](./break-glass.md) for the full procedure.

**Restore** — performed offline; the encrypted file is standard openssl, so it
restores anywhere with no Fleet-specific tooling:

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:"$FLEET_BACKUP_PASSPHRASE" \
  -in fleet-backup-YYYYMMDD-HHMMSS.sql.enc | psql "$FLEET_DATABASE_URL"
```

**Recovery when locked out** — use the bundled `fleetctl` CLI (ships in the backend image):

```bash
fleetctl create-admin <username> <password>   # new Super Administrator
fleetctl reset-mfa <username>                  # clear a user's MFA
fleetctl enable-user <username>                # re-enable + unlock
fleetctl rotate-ca                             # rotate the user CA
```

Note: SSH **session recordings** live on the recordings volume (`FLEET_RECORDING_DIR`),
not in the database — back that volume up alongside the database backup.

---

# Two-site warm standby (cross-site DR)

Everything above is **single-instance** DR (protect state, restore from an encrypted
backup). This section covers the **multi-site** posture: **two independent instances
at two sites** — an active **primary** and a warm **standby** — so that if the
primary site is lost you bring the standby up at **its own address** and keep
managing your fleet. It is a deliberate alternative to stretching one HA cluster
across the WAN (`high-availability.md`) and to federation (`federation.md`, a
single-pane model, not a DR model). The in-app **Disaster Recovery** page (nav;
`DR.Manage`) drives it.

> **What this is:** two *complete, independent* stacks, each with its own database,
> CA, jump host, WireGuard overlay, proxy, and domain — kept in sync by **PostgreSQL
> replication**, with one writable at a time. On failure you promote the standby and
> use its domain.
>
> **What this is not:** it is **not** zero-touch or shared-nothing magic. Fleet
> reflects replication state and *triggers* your orchestration; the actual database
> promotion, DNS changes, and jump-host WireGuard bring-up are steps you wire up. And
> it does **not** bring back hosts that die with a site — that is workload DR.

## Model: active / standby (never active / active)

Run exactly **one writable instance at a time.** PostgreSQL has no safe
multi-master, and two control planes each issuing certificates, mutating RBAC, and
appending to their own tamper-evident audit hash-chain would diverge irreconcilably.
The standby's PostgreSQL continuously replicates from the primary; you do **not**
write to it until you fail over.

## Requirement 1 — data parity ("up to date at failure")

- **Streaming replication** primary → standby: **async** (RPO = lag, seconds) or
  **synchronous** (zero loss, WAN latency cost). Fleet does not manage this — use
  native replication, Patroni, or a managed cross-region replica; Fleet only needs
  `FLEET_DATABASE_URL` pointed at whatever is currently primary. The DR page shows
  this instance's live posture (in-recovery + replay lag).
- **Identical secrets on both stacks** — mandatory: `FLEET_CA_PASSPHRASE` (**the
  linchpin** — the CA private key lives encrypted in `ca_keys`; a different CA means
  no host accepts the standby's certs), `FLEET_VAULT_PASSPHRASE`, `FLEET_JWT_SECRET`,
  `FLEET_CSRF_SECRET`. The in-RAM ephemeral cert vault is per-instance and rebuilt on
  demand — it is not replicated, and that is fine.
- **Recordings** (`FLEET_RECORDING_DIR`) are on disk, not in the DB — replicate the
  directory only if you want replay history to survive failover.

## Requirement 2 — web reachability (easy)

Each site keeps its **own proxy, TLS cert, and domain.** No VIP, no DNS failover of
the web domain — on failover, operators just go to the standby's domain. Accepting
"different address after failover" is exactly what lets you avoid every
shared-endpoint problem.

## Requirement 3 — host reachability (the hard part)

Hosts **physically at the primary site die with it** — moot, they are off. Hosts that
**survive but dial the primary's WG hub** (cloud/remote, or standby-site-local hosts
pointed at the primary) need one of:

- **Option A — fail the WireGuard endpoint *name* over:** repoint the WG endpoint DNS
  to the standby jump host, which holds the **replicated WG server private key** and
  rebuilds peers from the promoted DB (`wg addconf wg0 <(fleetctl wg-peers)`). Peers
  roam and re-handshake with no re-enrollment. Your *web* domains stay separate; only
  the *WG endpoint name* fails over. (This is `high-availability.md` §5 across sites.)
- **Option B — dual-home the hosts:** enroll each survive-critical host into **both**
  WG hubs. Nothing has to move; costs a second tunnel per host.

For a home-site DR where nearly all hosts are at the primary, this collapses to "the
survivors are the standby's own hosts, trivially reachable" — done.

## The Disaster Recovery console

**Disaster Recovery** (nav; `DR.Manage` — Super Administrator + Administrator by
default) provides:

- **Status:** configured role, whether this DB is a standby (in recovery) + replay
  lag, connected standbys when it is a primary, and peer-instance reachability.
- **Configuration:** role label, peer URL (health only), and **failover/failback
  webhooks**.
- **Force failover / Force failback:** run from the instance **taking over**. Each
  optionally runs `pg_promote()` on this DB (enable "Also promote this database" when
  the standby steps up), then POSTs the configured webhook, auditing every step
  (`dr.failover` / `dr.failback` / `dr.promote`, hash-chained).

**Scope boundary (by design):** the console is a **trigger + status surface**, not
the orchestrator. `pg_promote()` works only when this DB is actually a standby and
the role may run it (superuser-only unless you `GRANT EXECUTE ON FUNCTION
pg_promote`); the console surfaces the DB's error verbatim otherwise. The **DNS
repoint and jump-host WireGuard bring-up happen in your webhook.**

## Failover

**Planned:** quiesce the primary → confirm standby lag ≈ 0 (DR page) → on the
standby, **Force failover** with "Also promote this database" → point the standby's
`FLEET_DATABASE_URL` at the now-primary DB if needed → operators move to the standby
domain.

**Unplanned (primary down):** the taking-over instance must be running to serve the
console, but a Fleet pointed at a read replica cannot serve writes (including login)
until the DB is promoted — so break the bootstrap at the DB first (`pg_ctl promote` /
`SELECT pg_promote();` / your Patroni/managed failover), then start the standby's
Fleet against the promoted DB and use **Force failover** (DB promotion off) to fire
the DNS/WG webhook. `fleetctl` on the standby is the break-glass path when no UI is
up. **Hosts that died with the primary site do not come back** — that is workload DR.

## Failback

Not symmetric — it needs replication re-established the *other* way first:

1. Bring the old primary back; **re-seed its PostgreSQL as a fresh standby of the
   now-primary** (base backup or `pg_rewind`) — it cannot resume as primary with
   stale data.
2. Let it catch up (watch its DR page replay lag).
3. In a maintenance window, **Force failover on the old primary** with DB promotion,
   fire its webhook to move DNS/WG back, return operators to its domain.
4. Re-seed the other side as its standby to restore the original posture.

## What Fleet does vs. what you do

| Fleet does | You do |
|------------|--------|
| Show recovery/replication state + peer health | Set up and monitor PostgreSQL replication |
| Optionally run `pg_promote()` from the console | Grant `pg_promote` execution / run it via DB tooling |
| Fire a failover/failback webhook, audit every action | Wire the webhook to DNS repoint + standby jump-host WG bring-up |
| Keep CA/vault/RBAC/audit in the replicated database | Replicate the DB and keep the secret set identical |
| Manage every *surviving, reachable* host from the standby | Provide host reachability (Req. 3) + workload DR for the failed site |
