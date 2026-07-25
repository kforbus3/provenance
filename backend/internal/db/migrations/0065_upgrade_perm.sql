-- Register the System.Upgrade permission, which gates the in-UI upgrade flow
-- (uploading + applying a signed .fleetup bundle, draining, rollback). It is a
-- high-privilege, host-mutating capability, so it is granted to NO built-in role
-- except Super Administrator, which holds it implicitly via the Admin.All wildcard.
-- An operator may still delegate it explicitly to a custom role. Idempotent.
INSERT INTO permissions(key, description) VALUES
    ('System.Upgrade', 'Upload and apply Fleet Terminal upgrades')
ON CONFLICT (key) DO NOTHING;
