# Fleet Terminal — Certificate Lifecycle

Fleet Terminal authenticates SSH using **short-lived OpenSSH certificates** signed
by an internal certificate authority, instead of distributing long-lived user
keys. This document describes the full lifecycle: CA creation, ephemeral issuance,
renewal, revocation, rotation, and the data model.

## Actors & storage

| Component | Role |
|-----------|------|
| **CA** (`internal/ca`) | Creates/holds the signing keys; signs certificates |
| **Issuer** (`internal/identity`) | Mints ephemeral per-session keypairs + certs |
| **Identity Vault** (`internal/identity`) | Holds ephemeral private keys in RAM only |
| `ca_keys` table | CA key material (private key **encrypted at rest**) |
| `ssh_certificates` table | Metadata of every issued cert (**no private keys**) |
| `cert_revocations` table | Revoked serials (KRL source) |
| `ssh_cert_serial_seq` | Monotonic, never-reused serial source |

Relevant configuration (`internal/config`):

| Variable | Default | Meaning |
|----------|---------|---------|
| `FLEET_CA_PASSPHRASE` | — (required in prod, ≥16B) | encrypts the CA private key |
| `FLEET_USER_CERT_TTL` | `168h` (7 days) | ephemeral user certificate lifetime |
| `FLEET_CERT_RENEW_BEFORE` | `24h` | renew certs this far ahead of expiry |
| `FLEET_HOST_CERT_TTL` | `8760h` (365 days) | host certificate lifetime |

## 1. CA creation (bootstrap of trust)

On first backend startup, `InitBackground` calls `EnsureUserCA`, which creates a
**user CA** (`kind = 'user'`, `algo = ssh-ed25519`) if none is active:

- A keypair is generated; the private key is **encrypted with
  `FLEET_CA_PASSPHRASE`** and stored in `ca_keys.private_enc`. It never leaves the
  backend.
- The public key (authorized_keys form) is stored and exposed via
  `GET /api/v1/certificates/ca` (`activeUserCA`).

Operators install that public key on every managed host as a `TrustedUserCAKeys`
entry (see [host-enrollment-guide.md](./host-enrollment-guide.md)). From then on,
hosts accept any non-revoked, in-validity certificate the CA signs.

## 2. Ephemeral user certificate issuance (per login)

When a user logs in, a session hook fires the **Issuer**:

1. Generate a fresh `ssh-ed25519` keypair **in the in-RAM vault** (never persisted).
2. Allocate a unique serial from `ssh_cert_serial_seq`.
3. Sign a user certificate with principals `fleet` + the username, validity
   `now … now + FLEET_USER_CERT_TTL`, bound to the browser `session_id`.
4. Persist **metadata only** to `ssh_certificates` (serial, `ca_key_id`,
   `user_id`, `session_id`, `key_id`, `principals`, `public_key`, `issued_at`,
   `expires_at`, `audit_id`). The private key stays in the vault.

When the gateway dials a managed host it mints a **separate per-host certificate**
that carries both `fleet` — which authenticates the shared **jump-host** hop — and
a **host-scoped** principal `fleet-h-<hostID>` (or `fleet-login-h-<hostID>` for the
login-only tier) for the managed host itself. With `FLEET_HOST_SCOPED_ONLY=true`,
each managed host is enrolled to trust **only** its scoped principal (not `fleet`),
so the certificate authenticates on that one host and is rejected everywhere else,
even though it still carries `fleet` for the jump hop. See
[security-guide.md §13](./security-guide.md#13-migrating-to-host-scoped-principals).

## 3. Renewal

A background loop (`renewalLoop`, hourly) calls `RenewExpiring`, which re-signs
certificates that fall within `FLEET_CERT_RENEW_BEFORE` of expiry for still-active
sessions. This keeps long-lived browser sessions working without forcing
re-login, while individual certificates remain short-lived.

## 4. Session end

On logout (or session revocation), the session hook calls `DestroySession`:

- The ephemeral private key is **zeroized** in the vault.
- The session's certificates are revoked (recorded in `cert_revocations`).

Because keys are ephemeral and short-lived, a session's credentials are useless
once the session ends.

## 5. Revocation

Operators with `Certificate.Manage` can revoke a specific certificate by serial:

```
POST /api/v1/certificates/{serial}/revoke   { "reason": "compromised" }
```

This inserts into `cert_revocations`, stamps `ssh_certificates.revoked_at` /
`revoke_reason`, and audits `certificate.revoke`. The current revocation list is
available as a KRL:

```
GET /api/v1/certificates/krl   ->   { "revokedSerials": [12, 87, 145] }
```

Distribute the KRL to managed hosts (`RevokedKeys` in `sshd_config`) so revoked
certificates are rejected even before they expire.

## 6. CA rotation

Rotate the signing key when required (policy, suspected compromise):

```
POST /api/v1/certificates/ca/rotate   ->   { "status": "rotated", "activeCa": "<id>" }
```

- A new CA key is generated and marked active; the previous key is retired
  (`ca_keys.retired_at`) but **kept** so already-issued certificates still verify
  until they expire.
- The action is audited (`certificate.ca_rotate`).
- **Post-rotation:** distribute the new `activeUserCA` public key to all managed
  hosts' `TrustedUserCAKeys`. Until a host trusts the new CA, certificates signed
  by it will be rejected. New logins automatically use the new active CA.

Inspect CA state any time:

```
GET /api/v1/certificates/ca   ->   { "cas": [ … ], "activeUserCA": "ssh-ed25519 …" }
GET /api/v1/certificates       ->   recently issued certificates (metadata)
```

## 7. Host certificates

Host certificates (`kind = 'host'`, `FLEET_HOST_CERT_TTL` default 365 days) let
clients verify host identity. They follow the same model: signed by the host CA,
metadata recorded in `ssh_certificates`, revocable by serial. Operators with
`Host.RotateCertificate` rotate them as part of host maintenance.

## Lifecycle at a glance

```
 CA created (EnsureUserCA, key encrypted at rest)
        |
        v
 user logs in ── Issuer mints ephemeral keypair (RAM) + signs short-lived cert
        |                                   |
        |                          metadata -> ssh_certificates
        v
 cert used by gateway to reach hosts (hosts trust the CA)
        |
        +--> hourly renewal re-signs certs nearing expiry (active sessions)
        |
        +--> revoke by serial ----> cert_revocations ----> KRL (sshd RevokedKeys)
        |
        +--> CA rotate ----> old CA retired (kept for verify), new CA active
        |
        v
 logout / expiry ── ephemeral key zeroized, session certs revoked
```

See also: [security-guide.md](./security-guide.md) and
[certificate endpoints in api.md](./api.md#certificates-ca-lifecycle).
