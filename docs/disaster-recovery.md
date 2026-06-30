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
