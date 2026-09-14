# External secrets manager (vault-of-record)

A vault credential can be **external-backed**: instead of Provenance storing the secret material
(sealed at rest), the credential holds only a *reference* into an external secrets manager, and
Provenance fetches the value **on demand** at the point of use. This lets Provenance broker secrets from the
manager your organization already runs, without becoming a second copy of record.

Supported backends: **HashiCorp Vault KV (v2)**, **OpenBao KV (v2)** and **AWS Secrets Manager**.

OpenBao is a fork of Vault 1.14 and serves the same KV v2 API, so it shares the client and the
connection settings. It is still a distinct provider *name* rather than an alias: the name is
stored on every external-backed credential and shown in the UI, so an operator who chose OpenBao
sees OpenBao, errors name the server they actually configured, and existing credentials keep
saying which one they were created against if the two ever diverge.

## How it works

- An external-backed credential stores `external_provider` (e.g. `vault-kv`) and an
  `external_ref` (e.g. `secret/db/prod#password`). **No secret material is stored locally** — the
  local sealed blob is empty.
- Whenever the plaintext is needed — a reveal, an SSH/RDP credential injection, a brokered database
  or Kubernetes connection — Provenance fetches it live from the manager through the one central resolver
  (`internal/credresolve`), so the value is never cached and always reflects the manager's current
  contents.
- Because the manager is the source of record, Provenance **does not rotate** external-backed
  credentials (rotate them in the manager) and cannot re-seal them.
- Everything else is unchanged: locally-sealed credentials continue to work exactly as before.

## Configure the connection

**In the UI:** Settings → Infrastructure → **External secrets manager**. The token and AWS secret
key are sealed at rest with the same key as the OIDC and LDAP secrets and are never returned to
the browser — the screen is told only *whether* each is set, so leaving a credential field blank
means "keep the stored one". Clearing a connection is done by clearing its address, which is
visible and therefore deliberate. **Test the saved connection** checks reachability, and reads a
reference you give it to prove the token actually has access.

**Or by environment.** The environment is the baseline and saved settings are layered over it
**field by field**: a deployment that predates this screen has no saved row and keeps working
untouched, and an operator who fills in only the address has not thereby unset the token their
`.env` supplies. One exception: skip-TLS-verify is OR-ed rather than overwritten, because `false`
is indistinguishable from "not set" for a bool and silently turning off a verification bypass the
environment asked for would change how the connection is authenticated with nobody saying so.

Set the connection for whichever manager(s) you use (a credential picks its provider):

HashiCorp Vault KV:

    PROV_EXTSECRET_VAULT_ADDR=https://vault.internal:8200
    PROV_EXTSECRET_VAULT_TOKEN=<token with read on the KV paths you reference>
    # PROV_EXTSECRET_VAULT_CACERT=/etc/prov/vault-ca.pem   # optional (private CA)
    # PROV_EXTSECRET_VAULT_SKIP_VERIFY=true                 # DEV ONLY

AWS Secrets Manager:

    PROV_EXTSECRET_AWS_REGION=us-east-1
    PROV_EXTSECRET_AWS_ACCESS_KEY_ID=...
    PROV_EXTSECRET_AWS_SECRET_ACCESS_KEY=...
    # PROV_EXTSECRET_AWS_SESSION_TOKEN=...                  # optional (STS)
    # PROV_EXTSECRET_AWS_ENDPOINT=http://localstack:4566    # optional override (emulator/testing)

## Create an external-backed credential

In **Vault** → *New credential*, tick **Store in an external secrets manager**, pick the manager,
and enter the reference:

- **Vault KV reference** — `mount/path#field`, e.g. `secret/db/prod#password`. If the KV secret has
  exactly one field, `#field` may be omitted.
- **AWS Secrets Manager reference** — the secret name or ARN, optionally `#field` to extract one key
  when the secret's value is a JSON object, e.g. `prod/db#password`. Without `#field` the whole
  `SecretString` is returned.

The credential is then usable anywhere a vault credential is: reveal, host credential injection, the
database broker, and the Kubernetes broker. Grants, check-out/approval policies, and auditing apply
identically.

## Notes

- Scope the Vault token to least privilege — read access only to the KV paths Provenance references.
- The reference format is provider-specific; more providers (e.g. AWS Secrets Manager) slot into the
  same `internal/extsecret` interface.
