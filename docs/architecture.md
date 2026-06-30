# Fleet Terminal — Architecture

Fleet Terminal is a Privileged Access Management (PAM) platform for browser-based
SSH. It brokers every SSH session through a hardened gateway, issues short-lived
ephemeral SSH certificates instead of distributing long-lived keys, and records
an immutable, tamper-evident audit trail of every privileged action.

The backend is Go (chi router, pgx/PostgreSQL); the frontend is React + Vite
served by nginx. Everything runs through Docker Compose for local development —
no local Go/Node/Postgres toolchain is required (see the [Developer Guide](./developer-guide.md)).

---

## Component diagram

```
                         Operator's workstation
   +--------------------------------------------------------------+
   |  Browser (React SPA)                                          |
   |    - Login / Bootstrap / Dashboard / Hosts / Sessions / ...   |
   |    - xterm.js terminal, asciicast replay                      |
   +--------------------------------------------------------------+
              |   HTTPS (REST + JSON)         |  WSS (terminal bytes)
              |   Authorization: Bearer JWT   |  ?token=<access JWT>
              v                               v
   +--------------------------------------------------------------+
   |  Frontend container (nginx)  ── serves SPA, reverse-proxies   |
   |  /api and /metrics to the backend                            |
   +--------------------------------------------------------------+
              |  /api/v1/*   (REST)           |  /api/v1/terminal/{hostId} (WS)
              v                               v
   +--------------------------------------------------------------+
   |  Backend (Go, chi)                                            |
   |                                                              |
   |   HTTP modules        auth / RBAC          services          |
   |   ---------------      -------------        -----------       |
   |   bootstrap           RequireAuth          Store (pgx)        |
   |   auth                RequirePermission    CA (ssh-ed25519)   |
   |   hosts  enrollment   Principal            Issuer (ephemeral) |
   |   admin (users/...)   Audit chain          Identity Vault     |
   |   auditapi  system    (httpx helpers:      (in-RAM keys)      |
   |   sessionsapi          WriteJSON /         Gateway (sshgw)    |
   |   approvals            WriteError /        Recorder           |
   |   certificates         Decode / ParseID /  Monitor (health)   |
   |   terminal (WS)        Audit)              Scheduler engine   |
   |   sftp   scan                              Notifier           |
   |   playbook  scheduler                      Backup             |
   |   notify  backup                                              |
   |   assistant  monitor                                          |
   +--------------------------------------------------------------+
                              |  HTTP (mint ephemeral cert)
                              v
                    +---------------------------+
                    |  ansible-runner sidecar   |
                    |  (Python/Ansible; lints & |
                    |  runs playbooks, SSHes via |
                    |  the Jump Host)           |
                    +---------------------------+
        |                         |                       |
        | SQL (parameterized)     | mint/sign cert        | SSH (ephemeral cert)
        v                         v                       v
   +-----------+        +------------------+      +---------------------+
   | PostgreSQL|        | SSH User CA      |      |  SSH Gateway (sshgw)|
   | (+ Redis  |        | private key      |      |  egress through     |
   |  optional)|        | encrypted at rest|      |  the Jump Host      |
   +-----------+        +------------------+      +----------+----------+
                                                            |
                                                            v
                                                   +-----------------+
                                                   |   Jump Host     |
                                                   | (bastion / SSH  |
                                                   |  proxy egress)  |
                                                   +--------+--------+
                                                            |
                                                            v
                                                   +-----------------+
                                                   |  WireGuard mesh |
                                                   |  (wg tunnel net)|
                                                   +--------+--------+
                                                            |
                                          +-----------------+-----------------+
                                          v                 v                 v
                                   +-----------+     +-----------+     +-----------+
                                   | Managed   |     | Managed   |     | Managed   |
                                   | Host A    |     | Host B    |     | Host C    |
                                   | (host CA  |     |  trusts   |     |  trusts   |
                                   |  trusts   |     |  user CA) |     |  user CA) |
                                   |  user CA) |     +-----------+     +-----------+
                                   +-----------+
```

The full chain is: **Browser → HTTPS/WSS → React → REST → Backend → SSH Gateway
→ Jump Host → WireGuard → Managed Hosts.** Managed hosts are configured to trust
the Fleet user CA (`TrustedUserCAKeys`); the backend never needs to push or
manage `authorized_keys` per user.

---

## Request data flows

### 1. First run / bootstrap
1. The SPA calls `GET /api/v1/bootstrap/status`. If `bootstrapAvailable` is true
   (no users exist yet and `FLEET_ALLOW_BOOTSTRAP` is set), it renders the wizard.
2. `POST /api/v1/bootstrap/init` validates the password against the policy,
   Argon2id-hashes it, creates the first user with `is_super_admin = true`, and
   grants the built-in **Super Administrator** role.
3. The wizard self-closes the moment one user exists; it can only be reopened by
   an offline recovery process (see the [Disaster Recovery guide](./disaster-recovery.md)).

### 2. Login and ephemeral identity issuance
1. `POST /api/v1/auth/login` verifies the password, then `CreateSession` mints:
   - a short-lived **access JWT** (default 15m, HMAC-signed),
   - a rotating **refresh token** (HttpOnly cookie, default 30d), and
   - a **CSRF token** (double-submit cookie, readable by JS).
2. A session hook fires: the **Issuer** mints an ephemeral `ssh-ed25519` keypair
   in the **Identity Vault** (RAM only) and signs a short-lived user certificate
   (default 7d, principals `fleet` + username). Only certificate *metadata* is
   persisted in `ssh_certificates`; the private key never touches disk or the DB.
3. On `POST /api/v1/auth/logout` the session's ephemeral key is zeroized and its
   certificates revoked.

### 3. Opening a terminal
1. The SPA opens `WSS /api/v1/terminal/{hostId}?token=<access JWT>` (browsers
   cannot set `Authorization` on a WebSocket, so the short-lived token is passed
   as a query parameter and validated with `AuthenticateToken`).
2. The backend checks `Host.Connect`, then host authorization (group membership
   or an active temporary grant; super admins bypass).
3. The **Gateway** dials the target through the **Jump Host** over the WireGuard
   tunnel address, presenting the session's ephemeral certificate. A PTY is
   opened and bytes are relayed between the WebSocket and the SSH channel.
4. The **Recorder** writes the stream as an `asciicast-v2` recording; session
   metadata, byte counts, and an audit event are persisted.

### 4. Just-in-time access
A user without standing access requests time-boxed access to a host or group
(`POST /api/v1/approvals`). An approver decides (`POST /api/v1/approvals/{id}/decide`);
an approval mints a `temporary_permissions` grant that expires automatically and
is consulted during host authorization.

### 5. Ansible playbooks and the runner sidecar
Python and Ansible are kept out of the lean Go backend by isolating them in a
separate **`ansible-runner`** sidecar container (`deploy/ansible-runner`, a small
FastAPI service). The `playbook` module authors and stores playbooks, asks the
runner to `--syntax-check` / lint YAML, and orchestrates runs:

1. On a run, the backend mints a short-lived ephemeral key + user certificate
   for the privileged `fleet` principal (via `Issuer.SystemKeyMaterial`, default
   2h TTL) — the same in-RAM, never-persisted identity model used for terminals.
2. It resolves each target's jump-reachable address (WireGuard tunnel IP, or the
   direct address for skip-WireGuard hosts) and POSTs the playbook, inventory,
   ephemeral certificate, and jump-host coordinates to the runner.
3. The **sidecar** performs the actual SSH — connecting **through the Fleet jump
   host** using the supplied certificate — and streams run output back; the
   backend records the run and an audit event. The runner never holds long-lived
   keys and is reachable only on the internal compose network.

### 6. Scheduling, notifications, and backups
- The **`scheduler`** engine fires recurring scans and playbook runs, reusing the
  normal `scan` / `playbook` run paths so scheduled work appears in the usual
  history; fire times honor the app-wide display timezone setting.
- The **`notify`** service sends outbound **email (SMTP)** and **webhook**
  notifications on key events; the SMTP password is encrypted at rest.
- The **`backup`** service produces **encrypted database backups** under a
  retention policy; recovery (including break-glass access) is documented in the
  [break-glass runbook](./break-glass.md). The **`system`** module exposes
  background-job status and operational settings; the **`monitor`** service runs
  authenticated SSH health checks and caches per-host pending package updates;
  the **`assistant`** module answers questions over inventory, metrics, scans,
  playbook runs, and pending updates.

All HTTP modules share the **`internal/httpx`** helpers
(`WriteJSON` / `WriteError` / `Decode` / `ParseID` / `Audit`) for consistent
responses, request decoding, ID parsing, and best-effort audit writes.

---

## Security model

- **Ephemeral, in-RAM SSH keys.** Per-session SSH private keys are generated and
  held only in the in-process Identity Vault. They are never written to disk or
  the database and are zeroized on logout/expiry. The database stores only
  certificate metadata (`ssh_certificates`) — never private key material. The CA
  private key itself is stored encrypted at rest (`ca_keys.private_enc`,
  encrypted with `FLEET_CA_PASSPHRASE`) and never leaves the backend.

- **Short-lived certificates + KRL.** User certificates are short-lived (default
  7d) and auto-renewed ~24h before expiry by a background loop. Every certificate
  has a unique, never-reused serial (`ssh_cert_serial_seq`). Revocation is
  recorded in `cert_revocations` and exposed as a Key Revocation List via
  `GET /api/v1/certificates/krl`. CA rotation is a single API call.

- **Backend-authoritative RBAC.** Authorization is enforced server-side only.
  Every route is wrapped with `RequireAuth` + `RequirePermission("<Perm>")`;
  frontend permission checks are advisory. `Admin.All` is treated as a wildcard.

- **Hash-chained, tamper-evident audit.** Every state change appends a row to
  `audit_events` where `hash = H(prev_hash || canonical(event))`. The chain can
  be verified end-to-end via `GET /api/v1/audit/verify`, which returns the first
  broken sequence number if the chain has been altered. See the
  [Security Guide](./security-guide.md).

- **Defense in depth at the edge.** Access tokens are HMAC-signed JWTs; refresh
  and session cookies are HttpOnly, `Secure` (in production), and SameSite=Strict.
  State-changing cookie-authenticated requests require a double-submit CSRF token.
  All SQL is parameterized. Passwords are Argon2id with a configurable policy and
  account lockout.

- **Network isolation.** Managed hosts are never exposed directly. All SSH egress
  flows through the Jump Host and a WireGuard tunnel mesh, so the only inbound
  surface a managed host needs is the WireGuard endpoint.

See [database.md](./database.md) for the full schema and [api.md](./api.md) for
the endpoint reference.
