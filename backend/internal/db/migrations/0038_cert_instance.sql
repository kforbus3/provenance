-- Tag each ephemeral SSH certificate with the instance that issued it (and holds its
-- private key only in RAM). In HA the issue-own-cert model lets several instances
-- each hold a valid cert for the same session; when an instance dies its certs are
-- keyless, so a leader sweep revokes the dead instance's still-valid certs.
-- NULL = legacy/unknown issuer (pre-HA), which the sweep leaves alone.
ALTER TABLE ssh_certificates ADD COLUMN IF NOT EXISTS instance_id UUID;
