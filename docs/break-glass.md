# Break-Glass & Recovery Runbook

Fleet Terminal is the **single path** to your hosts. If the backend, database, or
CA is lost, you can lose access to the entire fleet at once. This runbook covers
(1) the secrets and backups that make recovery possible, (2) how to rebuild Fleet
from a backup, and (3) how to reach a host when Fleet itself is down.

> **Test this before you need it.** A backup you have never restored is a guess.
> Walk through "Rebuild Fleet from a backup" on a throwaway host at least once.

---

## 1. What you must protect (or recovery is impossible)

| Item | Where it lives | If you lose it |
| --- | --- | --- |
| **`FLEET_CA_PASSPHRASE`** | your `.env` (and your memory / password manager) | The CA private key in the DB can't be decrypted → you must **re-enroll every host**. |
| **`FLEET_BACKUP_PASSPHRASE`** | your `.env` / password manager | Encrypted backups can't be decrypted. (Falls back to the CA passphrase if unset.) |
| **Database backups** | `FLEET_BACKUP_DIR` (`/var/lib/fleet/backups`) | All state — users, RBAC, hosts, the (encrypted) CA key, audit — is gone. |
| **Jump host volumes** | `jump_wg`, `jump_ssh` Docker volumes (capture with `make backup-volumes`) | WireGuard peers + the SSH host key; recoverable by re-enrolling hosts, but tedious. |

**Store the two passphrases off the server** (a password manager or a sealed
envelope). They are not in the database backup — by design — so a stolen backup
isn't enough to decrypt anything.

---

## 2. Backups

Configure under **Settings → Backup & Restore**:

- **Automatic scheduled backups** — enable, set an interval and how many to keep.
  The backend runs `pg_dump` and encrypts it with `openssl` (AES-256-CBC,
  PBKDF2) into `FLEET_BACKUP_DIR`.
- **Back up now** — produce one immediately.
- **Download** — pull an encrypted backup to your workstation.

**Get the backups off the host.** A backup on the same disk that dies with the
host protects nothing. Map `FLEET_BACKUP_DIR` to off-host storage (an NFS mount,
an external disk, or rsync the directory to another machine on a cron).

The encrypted file format is standard openssl, so it restores **anywhere** with
no Fleet-specific tooling — see below.

### Also back up the state volumes (not in the DB dump)

The database backup does **not** include the jump host's identity or on-disk
media. Capture those Docker volumes alongside it so a rebuild is seamless:

```sh
make backup-volumes           # → ./volume-backups/{jump_wg,jump_ssh,recordings,scans}.tar.gz
```

- **`jump_wg`** — the jump host's WireGuard keypair + enrolled peers.
- **`jump_ssh`** — the jump host's SSH host key (so known_hosts pinning still matches).
- **`recordings`, `scans`** — session recordings and scan HTML reports (the DB holds
  only their paths).

Store `volume-backups/` off-host next to your encrypted DB backup. Without
`jump_wg`/`jump_ssh` you can still recover, but every host must be re-enrolled to
rebuild the WireGuard overlay. Run `make down-single` first for a fully consistent
snapshot (optional for the mostly-static jump host files).

---

## 3. Rebuild Fleet from a backup

On a fresh host (or after wiping a broken one):

1. **Restore config + state volumes first**, using the **same `.env`** — crucially
   the same `FLEET_CA_PASSPHRASE` (and `FLEET_BACKUP_PASSPHRASE`). Restoring the
   volumes *before* the first start means the jump host comes up with its original
   WireGuard and SSH-host identity, so the overlay and known_hosts pinning still
   line up and no host needs re-enrollment:
   ```sh
   git clone <repo> && cd fleet-terminal
   cp /secure/offsite/.env .env          # your saved env with the passphrases
   cp -r /secure/offsite/volume-backups ./volume-backups   # if you have them
   make restore-volumes                  # jump_wg, jump_ssh, recordings, scans
   make up-single
   ```
   (No volume backups? Skip `restore-volumes`; the stack still comes up, but you'll
   re-enroll each host to rebuild the WireGuard overlay.)
2. **Restore the database** from your latest encrypted backup:
   ```sh
   openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:"$FLEET_BACKUP_PASSPHRASE" \
     -in fleet-backup-YYYYMMDD-HHMMSS.sql.enc \
   | docker compose -f deploy/compose/docker-compose.yml \
       -f deploy/compose/docker-compose.jumphost.yml exec -T postgres \
       psql -U fleet -d fleet
   ```
   (Or pipe into `psql "$FLEET_DATABASE_URL"` from anywhere that can reach the DB.)
3. **Restart the backend** so it reloads the CA key from the restored DB:
   ```sh
   make down-single && make up-single
   ```
4. **Verify.** Log in, open a terminal to a host. Because the restored CA key is
   the **same** one the hosts already trust, certificate login works immediately —
   no re-enrollment needed.

If you could **not** preserve `FLEET_CA_PASSPHRASE`, the CA key can't be
decrypted: generate a new CA and **re-enroll every host** (the hosts must be
taught to trust the new CA). This is why the passphrase matters as much as the
backup.

---

## 4. Reaching a host while Fleet is down

Your managed hosts keep running a normal `sshd` even when Fleet is unavailable —
what's down is the **jump host + certificate** path Fleet brokers. To get in
out-of-band you need a credential that does **not** depend on Fleet's CA.

### Recommended: pre-provision a break-glass key (do this now, not in a crisis)

1. On your workstation, generate an **offline** keypair and store the private key
   somewhere safe (password manager / hardware token) — it must **never** live on
   the Fleet server:
   ```sh
   ssh-keygen -t ed25519 -f fleet-breakglass -C "fleet-breakglass"
   ```
2. Install the **public** key on each host, in the `fleet` account's
   `authorized_keys` (or a dedicated `breakglass` sudoer). During enrollment the
   host is reachable on the jump host's LAN; you can append it then, or push it
   later over an existing Fleet session:
   ```sh
   echo "ssh-ed25519 AAAA… fleet-breakglass" >> ~fleet/.ssh/authorized_keys
   ```
3. **Test it** from your workstation against one host (directly, or via the jump
   host's LAN address), then file the private key away.

When Fleet is down, SSH in with that key directly to the host's management
address (or through the jump host if only the backend is down):
```sh
ssh -i fleet-breakglass fleet@<host-management-ip>
```

> **Trade-off.** A standing emergency key is a standing credential — keep it
> offline, scope it to what you need, and rotate it periodically. If you prefer no
> standing key, the alternative is console/hypervisor access (hypervisor console,
> IPMI/BMC, cloud serial console) to the host, which needs no Fleet component at all.

### If the backend is down but hosts + jump host are healthy

Often only the backend/DB is broken. The fastest fix is usually to **rebuild the
backend from a backup** (section 3) rather than touch hosts at all — host trust
and WireGuard are intact, so a restored backend reconnects immediately.

---

## 5. Recovering after hardening locked Fleet out of its own host

**Symptom:** after a scan remediation (or manual hardening) is applied to the host
that runs Fleet, the web UI stops loading or SSH brokering stalls. Fleet flags such
rules **⚠ access-impacting** and requires an extra confirmation for control-plane
hosts, but if a fix still slipped through, recover from the console (or a
[break-glass key](#recommended-pre-provision-a-break-glass-key-do-this-now-not-in-a-crisis)).

> If `Defaults noexec` is active in sudoers (see below), run recovery as individual
> `sudo <cmd>` invocations — `noexec` blocks `sudo bash -c '…'` wrappers.

### Networking sysctls (most common — breaks Docker / WireGuard)

Hardening baselines (e.g. ANSSI-BP-028) set kernel networking sysctls that cut the
container bridge and the WireGuard overlay:

- `net.ipv4.ip_forward = 0` disables the Docker bridge's forwarding, so the
  published ports that serve the UI go dark.
- strict `rp_filter` / `route_localnet = 0` drop the asymmetric Docker/WireGuard paths.

These are typically written to `/etc/sysctl.conf`, which `sysctl --system` applies
**last** — so it overrides anything you add under `/etc/sysctl.d/`. Fix the values
in `/etc/sysctl.conf` itself, then reload and restart Docker:

```sh
# see what the remediation changed
sudo grep -nE 'ip_forward|rp_filter|route_localnet' /etc/sysctl.conf /etc/sysctl.d/
# in /etc/sysctl.conf set: ip_forward = 1, *.rp_filter = 2 (loose), route_localnet = 1
sudo sysctl --system
sudo systemctl restart docker      # rebuilds the bridge NAT / forward rules
```

If the host uses **kernel** WireGuard, ensure the module is loaded
(`sudo modprobe wireguard`); otherwise the jump host / enrollment fall back to
userspace `wireguard-go`.

### Sudo `noexec` / `requiretty` (breaks Fleet automation)

`Defaults noexec` or `requiretty` in sudoers stops Fleet's non-interactive
`sudo bash` (enrollment, remediation) from executing. Keep the hardening for
everyone else but exempt the account Fleet connects as — edit the offending file
with `visudo` and add, after the `Defaults` line it wrote:

```
Defaults:<fleet-ssh-user> !noexec
```

### Root / direct-login lockout

`no_direct_root_logins` and `sshd_*_root_login` fixes are usually fine to leave in
place — recover with a normal sudo account, not root. Only revert them if a
workflow genuinely needs direct root login.

> **Prevention.** Add Fleet's own host to `FLEET_CONTROL_PLANE_HOSTS` (or tag it
> `control-plane`) so remediating it always demands the extra confirmation, and
> prefer running host-hardening scans against managed hosts rather than the box
> that runs Fleet.

---

## 6. Periodic drill (quarterly)

1. Download the latest encrypted backup and **decrypt it** locally to confirm the
   passphrase works:
   ```sh
   openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:"$FLEET_BACKUP_PASSPHRASE" \
     -in fleet-backup-*.sql.enc | head
   ```
2. Restore it into a throwaway Postgres and confirm it loads.
3. SSH to one host with the **break-glass key** to confirm it still works.
4. Re-confirm both passphrases are in your password manager.

A recovery you've rehearsed is an inconvenience. One you haven't is an outage.
