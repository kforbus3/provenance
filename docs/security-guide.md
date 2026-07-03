# Fleet Terminal — Security Guide

Fleet Terminal is a Privileged Access Management platform; its security posture is
central to its purpose. This guide documents the controls, their configuration,
and operational recommendations.

## Threat model (summary)

- **No standing SSH keys.** Compromise of a single managed host must not yield
  reusable credentials for the rest of the fleet.
- **Tamper-evident accountability.** An attacker (including an insider with DB
  access) must not be able to silently alter the record of what happened.
- **Backend-authoritative authorization.** A malicious or buggy client must not be
  able to bypass access control.
- **Network isolation.** Managed hosts must not be directly reachable.

## 1. Ephemeral, in-RAM SSH identities

- On login, the **Issuer** generates a fresh `ssh-ed25519` keypair in an
  in-process **Identity Vault** and signs a short-lived user certificate
  (default TTL 7 days, `FLEET_USER_CERT_TTL`), bound to the browser session with
  principals `fleet` + username.
- **Private keys never touch disk or the database.** Only certificate *metadata*
  is persisted in `ssh_certificates` (serial, principals, public key, validity,
  `key_id`). On logout the key is zeroized and its certificates revoked.
- A background loop renews certificates ~24h before expiry
  (`FLEET_CERT_RENEW_BEFORE`) so active sessions don't break.
- **Unique per-host certificates.** Connecting to a host mints a credential scoped
  to that specific `(session, host)` pair — distinct key material and serial per
  host. The blast radius of any single credential is one host. The vault zeroizes a
  session's session-level **and** all per-host keys together on teardown.
- **Host-scoped principals.** Each certificate is stamped with a principal unique
  to its target host, `fleet-h-<hostID>` (or `fleet-login-h-<hostID>` for the
  login-only tier), and enrollment configures each host to accept only its own.
  A certificate — even if its private key were somehow extracted — is therefore
  **rejected by every host except the one it was minted for**, so it cannot be
  replayed to reach a host the user was never granted. This also bounds the Ansible
  playbook runner: its run credential is scoped to just that run's target hosts, so
  a playbook that reads the key off the runner still can't escape to the rest of the
  fleet. Rollout is backwards compatible and gated by `FLEET_HOST_SCOPED_ONLY` —
  see [§13](#13-migrating-to-host-scoped-principals).

## 2. Certificate authority hardening

- The CA private key is stored **encrypted at rest** in `ca_keys.private_enc`,
  encrypted with `FLEET_CA_PASSPHRASE` (≥16 bytes, required in production). It
  never leaves the backend process. The CA **public** key is served unauthenticated
  at `GET /api/v1/certificates/ca/pub` — it is not secret (it is installed as
  `TrustedUserCAKeys` on every host); a co-located jump host uses it to self-trust.
- Every issued certificate has a unique, **never-reused serial** from
  `ssh_cert_serial_seq`, enabling precise revocation.
- **Revocation** is recorded in `cert_revocations` and published as a Key
  Revocation List via `GET /api/v1/certificates/krl`.
- **CA rotation** is a single API call (`POST /api/v1/certificates/ca/rotate`);
  the previous CA is retired (`ca_keys.retired_at`) but kept for verification of
  already-issued certs. See [certificate-lifecycle.md](./certificate-lifecycle.md).

## 3. Hash-chained, tamper-evident audit

- Every state change appends a row to `audit_events` where
  `hash = H(prev_hash || canonical(event))`, forming an append-only chain ordered
  by `seq`.
- `actor_name` is denormalized so accountability survives user deletion.
- **Verify integrity** with `GET /api/v1/audit/verify` →
  `{"intact": true, "brokenAtSeq": 0}`. A non-zero `brokenAtSeq` pinpoints the
  first altered/missing row. Run this on a schedule and alert on failure.
- **Export** the full chain with `GET /api/v1/audit/export` (streamed JSON) for
  off-box archival; archive to write-once/immutable storage for strongest
  guarantees.
- **Audit forwarding (SIEM).** Every audit event can additionally be streamed to
  an external collector — **syslog** (RFC 5424, UDP or TCP) or **HTTP JSON**.
  Forwarding is **off by default**, configured in the UI, and **best-effort**: the
  in-app hash-chained log remains the **system of record**, so a SIEM outage never
  blocks operations or breaks the chain. Use it to centralize/correlate events,
  not as a substitute for the tamper-evident chain.

## 4. Authentication & sessions

- **Passwords:** Argon2id hashing, stored separately from the user row in
  `user_credentials` (least privilege on reads). A configurable `password_policy`
  enforces length/complexity and a no-reuse `pw_history`. `must_change_pw` forces
  rotation; resets can require a change at next login.
- **Lockout:** `lockout_policy` (default 5 failed attempts → 15-minute lockout)
  via `failed_logins` / `locked_until`. Admins can unlock with
  `POST /users/{id}/unlock`.
- **Tokens:** short-lived **access JWTs** (HMAC, `FLEET_JWT_SECRET`, default 15m)
  carried as `Authorization: Bearer`. Rotating **refresh tokens** (default 30d)
  are stored only as hashes (`sessions.refresh_hash`).
- **Cookies:** refresh (`fleet_refresh`) and session-id (`fleet_sid`) cookies are
  HttpOnly, `Secure` (when `FLEET_COOKIE_SECURE=true`), and SameSite=Strict,
  scoped to `/api/v1/auth`. The CSRF cookie (`fleet_csrf`) is JS-readable by
  design (double-submit).
- **MFA:** `mfa_methods` supports TOTP and WebAuthn (passkeys). MFA is optional by
  default and can be **enforced**: globally via the `require_mfa` setting (Users →
  *Require MFA for all*) or per user via the `require_mfa` flag. When required and
  no factor is enrolled, login issues **no session** until the user completes
  forced TOTP enrollment. Prefer passkeys (phishing-resistant) for internet
  exposure.
- **External identity providers (SSO).** In addition to local accounts, Fleet can
  delegate sign-on to an external IdP; each user carries an `auth_source`
  (`local` | `oidc` | `ldap`), and **external accounts cannot use a local
  password**. Both providers are configured in **Settings** (`System.Configure`)
  and support **find-or-provision** with **group→role mapping**:
  - **OIDC single sign-on** (Okta, Azure AD, Google, Keycloak, Authentik) over
    the authorization-code flow with **PKCE**. ID tokens are **JWKS-verified**
    (signature, issuer, audience, and nonce). The OIDC **client secret is sealed
    at rest** (`secretbox`, keyed by `FLEET_CA_PASSPHRASE`) and never returned by
    the API.
  - **LDAP / Active Directory** sign-on via a service-account lookup followed by a
    user-bind password verification, with group→role mapping by **CN**. Supports
    `ldap://` / `ldaps://` and **StartTLS**; the **bind password is sealed at
    rest** (`secretbox`, keyed by `FLEET_CA_PASSPHRASE`).
  - **Trade-off:** SSO **bypasses Fleet's local password and MFA** — the IdP is
    the authenticator, so enforce strong authentication (MFA, conditional access)
    at the IdP. Local-account controls (lockout, password policy, Fleet MFA) apply
    only to `auth_source=local` users.
- **Session reaping:** a background loop enforces idle (`FLEET_SESSION_IDLE_TTL`)
  and absolute (`FLEET_SESSION_ABSOLUTE_TTL`) limits even for connections that
  make no further HTTP requests. Logout, idle/absolute timeout, and account
  disable/terminate all **force-close live terminals and in-flight SFTP
  transfers** and revoke the session's certificates.

## 5. Authorization (RBAC)

- Authorization is enforced **server-side only**. Frontend permission checks are
  advisory. Every protected route is wrapped with `RequireAuth` +
  `RequirePermission("<Perm>")`.
- `Admin.All` (held by Super Administrators) is a wildcard that satisfies any
  check. Use it sparingly.
- **Host access** is a separate gate from the RBAC permission: even with
  `Host.Connect`, a user must reach the host via a **shared group**, a **direct
  user→host grant** (`host_users`), or an active **temporary grant** — super
  admins bypass. Enforced on every terminal, SFTP, and **OpenSCAP scan**
  (`UserCanAccessHost`). Users have no host access by default.
- **Root vs. login-only on the host** is gated by `Host.Sudo`. Each enrolled host
  has two shared accounts: a privileged one (`fleet`, NOPASSWD sudo) and a
  login-only one (`fleet-login`, no sudo). The backend issues a certificate whose
  principal maps to the privileged account only when the user has `Host.Sudo` (or
  is a super admin); otherwise it maps to the login-only account. The split is
  enforced by sshd via `AuthorizedPrincipalsFile` (distinct principals per
  account), so a login-only certificate cannot open the sudo account. The
  principals are **host-scoped** (`fleet-h-<hostID>` / `fleet-login-h-<hostID>`),
  so the account split holds and the certificate is only valid on its own host.
  Both tiers still use unique per-user certs and are recorded and audited.
- **Automation permissions (admin-only by default).** Three permissions gate the
  Ansible/scheduling features and are granted to the Administrator role only:
  - **`Playbook.Run`** is effectively **arbitrary root-level command execution
    across hosts** — running a playbook applies changes on the targets through
    Fleet's SSH path. It is therefore admin-only by default and granted
    *separately* from `Playbook.Edit`. It is still **access-scoped** (the runner
    can only target hosts the user can reach, via `UserCanAccessHost`) and every
    run is **audited**. Treat granting it like granting root on the fleet.
  - **`Playbook.Edit`** — author, upload, edit, delete, validate/lint playbooks
    (no execution).
  - **`Schedule.Manage`** — create and manage scheduled scans and playbook runs.
- Prefer **least privilege**: narrow custom roles plus just-in-time approvals
  over broad standing access.

## 6. CSRF & transport

- State-changing, **cookie-authenticated** requests (`refresh`, `logout`) require
  the double-submit header `X-CSRF-Token` to match the `fleet_csrf` cookie.
  Bearer-only API calls don't rely on cookies and are exempt.
- CORS is restricted to `FLEET_PUBLIC_URL` (plus localhost dev origins) with
  credentials. Terminate TLS at the edge and set `FLEET_COOKIE_SECURE=true`.

## 7. WebSocket terminal

- Browsers can't set `Authorization` on a WebSocket, so the **short-lived access
  token** is passed as the `?token=` query parameter and validated with
  `AuthenticateToken`. Because it is short-lived, exposure window is minimal —
  still, terminate TLS so the URL isn't observable on the wire.
- The endpoint re-checks `Host.Connect` and host authorization before opening the
  PTY.

## 8. SQL & input handling

- **All** database access uses parameterized SQL via the store layer — no string
  concatenation of user input.
- UUIDs and serials are parsed/validated before use; invalid input returns `400`.

## 9. Network isolation

- Managed hosts are reachable only through the **jump host** and a **WireGuard**
  tunnel mesh. The only inbound surface a managed host needs is the WireGuard
  endpoint; SSH is not exposed publicly.
- Host SSH host keys are pinned (`host_fingerprints`, `SHA256:…`) to detect MITM.

## 10. Secrets & configuration

- In `production`, the backend **refuses to start** without strong
  `FLEET_JWT_SECRET` (≥32B), `FLEET_CSRF_SECRET` (≥16B), and
  `FLEET_CA_PASSPHRASE` (≥16B). In `development` it falls back to **insecure
  deterministic defaults** — never run production that way.
- Generate secrets with `openssl rand -hex 32`. Inject via your secret manager
  (`deploy/k8s/11-secret.yaml` for Kubernetes), not committed files.
- **`FLEET_BACKUP_PASSPHRASE`** encrypts database backups (`openssl` AES-256-CBC,
  PBKDF2). If unset it **falls back to `FLEET_CA_PASSPHRASE`**. Like the CA
  passphrase it is deliberately **not** stored in any backup — keep an offline
  copy in a password manager. See [break-glass.md](./break-glass.md) and
  [disaster-recovery.md](./disaster-recovery.md).
- **Other secrets encrypted at rest in the DB.** The SMTP / notification password
  is sealed (`secretbox`, keyed by `FLEET_CA_PASSPHRASE`) and never returned by
  the API — like the CA private key, it is stored only as ciphertext.

## 11. Rate limiting & abuse resistance

- A per-IP **token-bucket rate limiter** throttles abusive clients, with a
  stricter budget on `/auth` and `/bootstrap` than the rest of the API
  (`FLEET_AUTH_RATE_LIMIT_*` vs `FLEET_RATE_LIMIT_*`; `0` disables). Over-limit
  requests get `429`. This complements — does not replace — per-account lockout.
- The client IP is taken from `X-Forwarded-For`, so it is only trustworthy when
  the app sits **behind a reverse proxy** that sets it. Never expose the backend
  directly to the internet. For internet-facing deployments add edge defenses
  (WAF, fail2ban, CAPTCHA) — see [internet-exposure.md](./internet-exposure.md).

## 12. Monitoring & response

- Scrape `GET /metrics` (Prometheus): HTTP request counts/latency plus session and
  gateway metrics. Alert on auth-failure spikes and audit-verify failures.
- `auth_events` provides a fast, queryable security event stream
  (`login_failure`, `lockout`, `mfa_*`, `pw_change`) independent of the audit
  chain.
- On suspected compromise: revoke affected certificates (or rotate the CA),
  disable/lock the user, verify the audit chain, and review `auth_events` and
  `ssh_sessions`. See [Disaster Recovery](./disaster-recovery.md).

## 13. Migrating to host-scoped principals

Host scoping binds every certificate to a single host so it can't be replayed
elsewhere (see [§4](#4-authentication)/[§5](#5-rbac--authorization)). It rolls out
in two stages with **no window in which a host is locked out**:

**Stage 1 — deploy (already backwards compatible).** With `FLEET_HOST_SCOPED_ONLY`
unset/`false`:
- Newly issued per-host certs carry **both** the fleet-wide `fleet` principal and
  the host-scoped `fleet-h-<hostID>`. They authenticate on hosts old and new.
- **Re-enroll each host** (Hosts → the host → *Re-enroll*, or the pipe-enroll
  script). Re-enrollment rewrites `/etc/ssh/auth_principals/*` to trust that host's
  scoped principal. A re-enrolled host immediately **stops accepting** any other
  host's certificate, while still honoring `fleet` for anything not yet migrated.
- Do this for every host, including the jump host's managed peers. Monitoring,
  scans, SFTP, and playbook runs continue working throughout.

**Stage 2 — lock down.** Once **every** host has been re-enrolled, set
`FLEET_HOST_SCOPED_ONLY=true` and restart the backend:
- Certs are then minted with **only** the host-scoped principal — the fleet-wide
  `fleet` is dropped from user, system (monitor/scan/support/KRL), and playbook
  credentials.
- Re-enroll once more (or let scheduled enrollment refresh) so hosts stop trusting
  `fleet` entirely. From here a leaked certificate is useless anywhere but its one
  host.

> **Ordering matters.** Do not set `FLEET_HOST_SCOPED_ONLY=true` before every host
> is re-enrolled: a host that still trusts only `fleet` will reject the now
> scoped-only certificates and become unreachable until you re-enroll it. If that
> happens, unset the flag (or re-enroll the host over its bootstrap credentials) to
> recover. The jump host itself is unaffected — the session cert used to reach it is
> separate and always retains the `fleet` principal.

## Security checklist (production)

- [ ] Strong `FLEET_JWT_SECRET`, `FLEET_CSRF_SECRET`, `FLEET_CA_PASSPHRASE` set.
- [ ] `FLEET_ENV=production`, `FLEET_COOKIE_SECURE=true`, TLS at the edge.
- [ ] `FLEET_ALLOW_BOOTSTRAP=false` after initial setup.
- [ ] **Require MFA** globally (or per user); prefer passkeys.
- [ ] Per-IP rate limits set; app only reachable behind a reverse proxy.
- [ ] Scheduled `audit/verify` with alerting; audit exports archived immutably.
- [ ] Least-privilege roles; `Admin.All` limited to break-glass accounts.
- [ ] CA public key distributed; rotation and revocation procedures rehearsed.
- [ ] Managed hosts reachable only via jump host + WireGuard.
- [ ] All hosts re-enrolled, then `FLEET_HOST_SCOPED_ONLY=true` for host-scoped certs.
- [ ] Database and recordings backed up and restore-tested.
