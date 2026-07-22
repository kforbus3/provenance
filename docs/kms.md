# External KMS / HSM for master-key protection

Fleet seals its at-rest secrets — the SSH CA signing key (`ca_keys.private_enc`) and every
credential-vault entry (`vault_secret_versions.sealed`) — with **AES-256-GCM**, using a passphrase
derived per record (argon2id, or PBKDF2 under FIPS). See `internal/secretbox`.

By default those passphrases are supplied as environment variables
(`FLEET_CA_PASSPHRASE`, `FLEET_VAULT_PASSPHRASE`). An external **Key Management Service (KMS)** or
**HSM** lets you keep them off disk in plaintext: you store only a KMS-**wrapped** blob, and Fleet
asks the KMS to unwrap it into memory once at boot.

## Threat model / what this buys you

- An attacker who steals the disk, a database dump, or an environment file gets only the *wrapped*
  passphrase. Without live, authorized access to the KMS key they cannot unwrap it, so they cannot
  decrypt the CA key or any vault secret.
- The KMS key never leaves the KMS/HSM; Fleet only ever sends a small ciphertext to unwrap.
- Every unwrap is authorized and audited by the KMS itself (in addition to Fleet's own audit log).

It does **not** change the on-disk sealed-data format. Enabling or disabling a KMS backend needs no
migration and no re-seal — only the passphrase *source* moves.

## Providers

| Provider        | `FLEET_KMS_PROVIDER` | Notes |
|-----------------|----------------------|-------|
| Local (default) | `local`              | No external KMS. Passphrases read from the environment. Behavior unchanged. |
| HashiCorp Vault Transit | `vault-transit` | Vault's encryption-as-a-service. The key never leaves Vault. |
| AWS KMS         | `aws-kms`            | KMS Encrypt/Decrypt. Endpoint override supports KMS-compatible emulators. |

Both external providers are implemented against the vendor HTTP API directly — **no cloud SDK
dependency**. Azure Key Vault and GCP KMS slot into the same `internal/kms` interface.

## Configuration

Common:

    FLEET_KMS_PROVIDER=vault-transit        # or aws-kms, or local (default)
    FLEET_KMS_KEY_ID=fleet-master           # transit key name, or AWS key id/ARN/alias

HashiCorp Vault Transit:

    FLEET_KMS_VAULT_ADDR=https://vault.internal:8200
    FLEET_KMS_VAULT_TOKEN=<token with encrypt/decrypt on transit/keys/fleet-master>
    FLEET_KMS_VAULT_CACERT=/etc/fleet/vault-ca.pem   # optional, for a private CA
    # FLEET_KMS_VAULT_SKIP_VERIFY=true               # DEV ONLY — refused in production

AWS KMS:

    FLEET_KMS_AWS_REGION=us-east-1
    FLEET_KMS_AWS_ACCESS_KEY_ID=...
    FLEET_KMS_AWS_SECRET_ACCESS_KEY=...
    # FLEET_KMS_AWS_SESSION_TOKEN=...                 # optional (STS)
    # FLEET_KMS_AWS_ENDPOINT=http://localstack:4566   # optional override (emulator/testing)

## One-time setup: wrap your passphrases

With the KMS environment set, wrap each passphrase and capture the printed blob:

    # CA passphrase (pipe on stdin so it isn't captured in shell history):
    printf '%s' "$FLEET_CA_PASSPHRASE" | fleetctl kms wrap
    # -> vault:v1:AAAA...        (or awskms:v1:....)

    printf '%s' "$FLEET_VAULT_PASSPHRASE" | fleetctl kms wrap
    # -> vault:v1:BBBB...

Then in your deployment environment, **replace the plaintext passphrases with the wrapped blobs**:

    # remove (or leave unset):  FLEET_CA_PASSPHRASE / FLEET_VAULT_PASSPHRASE
    FLEET_CA_PASSPHRASE_WRAPPED=vault:v1:AAAA...
    FLEET_VAULT_PASSPHRASE_WRAPPED=vault:v1:BBBB...

You can wrap only one of the two if you prefer a phased rollout; a plaintext value and a wrapped
value can coexist across the CA and vault passphrases.

On the next boot Fleet logs `master passphrases unsealed via external KMS` and operates normally.
If the KMS is unreachable or the key is wrong, boot **fails closed** — Fleet does not start with an
unusable CA/vault.

## Verifying

- `fleetctl kms status` — prints the provider, key ID, which passphrases are wrapped, and a live
  health check against the backend.
- Settings → Infrastructure → **Encryption at rest** — the same status in-product (read-only),
  including backend health and per-passphrase wrapped/plaintext state. `GET /kms/status`
  (System.Configure).
- `fleetctl kms unwrap <blob>` — unwraps a blob to confirm it round-trips (prints the plaintext, so
  use with care).

## Rotating the KMS key

Because wrapping is independent of the sealed data, rotating the *KMS* key does not touch the CA key
or vault secrets. Re-wrap the same passphrases under the new key and swap the `*_WRAPPED` values:

    printf '%s' "$FLEET_CA_PASSPHRASE" | FLEET_KMS_KEY_ID=fleet-master-v2 fleetctl kms wrap

Rotating the *passphrase itself* (not the KMS key) is the existing at-rest re-seal flow
(`fleetctl fips reseal-secrets` re-seals to a new envelope); KMS wrapping layers on top of whichever
passphrase is current.

## Notes

- KMS wrapping is orthogonal to FIPS mode: it protects *where the passphrase lives*, while the FIPS
  profile governs *which KDF/cipher* seals the data. They compose.
- The identity vault (ephemeral per-session SSH keys, `internal/identity/vault.go`) is RAM-only and
  never persisted, so it is not a KMS target.
