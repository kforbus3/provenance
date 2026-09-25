-- A CA rotation in two phases: trusted first, signing second.
--
-- Rotating used to make the new key the signer the instant it was created, before
-- anything trusted it. Every certificate issued from then on was signed by a key the
-- jump host would not learn for up to five minutes, and that a host missing the trust
-- push would never learn at all. The old key could not be retired either: nothing
-- called RetireCAKey, so a rotation for a suspected compromise left the compromised key
-- trusted on every host for ever.
--
-- signing_since marks the key that signs. A new key is inserted active (trusted, and
-- pushed to hosts) with no signing_since, and is promoted -- given one -- only once every
-- enrolled SSH host and the jump host have confirmed they trust it. Every key that is
-- signing today is the one that was already signing, so it is backfilled from its
-- creation time and nothing changes on upgrade.
ALTER TABLE ca_keys ADD COLUMN IF NOT EXISTS signing_since timestamptz;
UPDATE ca_keys SET signing_since = created_at WHERE active AND signing_since IS NULL;

-- What each host has CONFIRMED it trusts: a hash of the CA key set it read back after
-- the last successful push. The gate for promoting a new key and for retiring an old
-- one is "every enrolled SSH host confirms the current set", and the background
-- reconcile retries exactly the hosts that do not.
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS ca_trust_hash text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS ca_trust_confirmed_at timestamptz,
    ADD COLUMN IF NOT EXISTS ca_trust_error text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS ca_trust_attempted_at timestamptz;
