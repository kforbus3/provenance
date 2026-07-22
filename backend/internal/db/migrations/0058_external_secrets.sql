-- External-backed vault secrets: a credential can reference material held in an
-- external secrets manager (e.g. HashiCorp Vault KV) instead of storing a locally
-- sealed blob. When external_provider is set, Fleet fetches the value on demand from
-- the manager at point of use (and stores no ciphertext for it). Existing secrets have
-- NULL here and are unchanged (local sealed material as before).
ALTER TABLE vault_secrets ADD COLUMN IF NOT EXISTS external_provider TEXT NOT NULL DEFAULT '';
ALTER TABLE vault_secrets ADD COLUMN IF NOT EXISTS external_ref TEXT NOT NULL DEFAULT '';
