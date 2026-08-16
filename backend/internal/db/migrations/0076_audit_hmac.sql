-- Key the audit hash chain with HMAC-SHA256 and record, per row, which algorithm
-- produced its hash so the chain stays verifiable across the upgrade.
--
-- Before this change the chain was a KEYLESS SHA-256: hash = SHA256(prev_hash ||
-- canonical(event)). Anyone with DB write access could rewrite an event and
-- recompute a valid chain, and VerifyAuditChain would still pass. New rows are now
-- MAC'd with a server-held key (cfg.AuditHMACKey) over a canonical record that also
-- binds seq, created_at and tenant_id -- none of which were covered before.
--
-- MIGRATION SCHEME (no rewrite of history):
--   hash_alg = 1  -> legacy keyless SHA-256 over the OLD canonical
--                    (actor_id|actor_name|action|target_kind|target_id|ip|detail).
--                    Every pre-existing row keeps this value (the column DEFAULT),
--                    so VerifyAuditChain re-derives it WITHOUT the key and existing
--                    chains still verify -- nothing reports "tampered" after upgrade.
--   hash_alg = 2  -> HMAC-SHA256(key) over the NEW canonical, which additionally
--                    binds seq, created_at and tenant_id. Written for every new row
--                    once an AuditHMACKey is configured.
-- The prev_hash link is unbroken across the 1->2 boundary: the first alg-2 row
-- chains to the last alg-1 row's hash, so the single global chain is continuous and
-- the keyed portion is tamper-evident from the first keyed row onward.
--
-- If no key is configured, new rows fall back to hash_alg = 1 (keyless) and the
-- backend logs a warning; the deployment keeps working exactly as before.

ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS hash_alg SMALLINT NOT NULL DEFAULT 1;

COMMENT ON COLUMN audit_events.hash_alg IS
    '1 = legacy keyless SHA-256 chain; 2 = HMAC-SHA256 keyed chain binding seq, created_at and tenant_id.';
