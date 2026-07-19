-- Host connection protocol. Hosts default to SSH (Fleet's ephemeral-certificate
-- terminal/SFTP). A host with protocol 'rdp' is a Windows (or other RDP) desktop
-- brokered through guacd; it authenticates with a vaulted credential (auth_method
-- vault_password + credential_id) and connects on rdp_port (default 3389).
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS protocol TEXT NOT NULL DEFAULT 'ssh', -- ssh | rdp
    ADD COLUMN IF NOT EXISTS rdp_port INT NOT NULL DEFAULT 3389;
