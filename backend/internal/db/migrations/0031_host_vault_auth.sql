-- Host authentication method. By default a host authenticates with Fleet's
-- ephemeral SSH certificates (fleet_cert). A host that cannot use certificates
-- (appliances, network gear, legacy systems) can instead authenticate with a
-- credential from the vault, injected at connection time so the operator never
-- sees it: vault_password (ssh.Password) or vault_ssh_key (a private key).
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS auth_method   TEXT NOT NULL DEFAULT 'fleet_cert', -- fleet_cert | vault_password | vault_ssh_key
    ADD COLUMN IF NOT EXISTS credential_id UUID REFERENCES vault_secrets(id) ON DELETE SET NULL;
