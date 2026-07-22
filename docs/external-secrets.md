# External secrets manager (vault-of-record)

A vault credential can be **external-backed**: instead of Fleet storing the secret material
(sealed at rest), the credential holds only a *reference* into an external secrets manager, and
Fleet fetches the value **on demand** at the point of use. This lets Fleet broker secrets from the
manager your organization already runs, without becoming a second copy of record.

Today the supported backend is **HashiCorp Vault KV (v2)**.

## How it works

- An external-backed credential stores `external_provider` (e.g. `vault-kv`) and an
  `external_ref` (e.g. `secret/db/prod#password`). **No secret material is stored locally** — the
  local sealed blob is empty.
- Whenever the plaintext is needed — a reveal, an SSH/RDP credential injection, a brokered database
  or Kubernetes connection — Fleet fetches it live from the manager through the one central resolver
  (`internal/credresolve`), so the value is never cached and always reflects the manager's current
  contents.
- Because the manager is the source of record, Fleet **does not rotate** external-backed
  credentials (rotate them in the manager) and cannot re-seal them.
- Everything else is unchanged: locally-sealed credentials continue to work exactly as before.

## Configure the connection

Set these on the backend (one connection serves all external-backed credentials):

    FLEET_EXTSECRET_VAULT_ADDR=https://vault.internal:8200
    FLEET_EXTSECRET_VAULT_TOKEN=<token with read on the KV paths you reference>
    # FLEET_EXTSECRET_VAULT_CACERT=/etc/fleet/vault-ca.pem   # optional (private CA)
    # FLEET_EXTSECRET_VAULT_SKIP_VERIFY=true                 # DEV ONLY

## Create an external-backed credential

In **Vault** → *New credential*, tick **Store in an external secrets manager** and enter the
reference:

- **Vault KV reference** — `mount/path#field`, e.g. `secret/db/prod#password`. If the KV secret has
  exactly one field, `#field` may be omitted.

The credential is then usable anywhere a vault credential is: reveal, host credential injection, the
database broker, and the Kubernetes broker. Grants, check-out/approval policies, and auditing apply
identically.

## Notes

- Scope the Vault token to least privilege — read access only to the KV paths Fleet references.
- The reference format is provider-specific; more providers (e.g. AWS Secrets Manager) slot into the
  same `internal/extsecret` interface.
