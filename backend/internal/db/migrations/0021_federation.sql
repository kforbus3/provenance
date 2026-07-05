-- Multi-site federation. Purely additive: a standalone instance never reads or
-- writes these tables. A hub uses the control + read-cache tables; a site uses
-- the site-side control tables. gen_random_uuid() is core in PostgreSQL 13+.

-- ---------------------------------------------------------------------------
-- Hub-side control
-- ---------------------------------------------------------------------------

-- A remote site that has joined this hub. Trust is by the site's Ed25519 public
-- key (no shared secret). status: pending -> active on first link; revoked ends it.
CREATE TABLE IF NOT EXISTS federation_sites (
    id                 uuid PRIMARY KEY,           -- site_id, allocated at join
    name               text NOT NULL,
    public_key         bytea NOT NULL,             -- site identity Ed25519 pubkey
    pending_public_key bytea,                       -- during site-key rotation
    status             text NOT NULL DEFAULT 'pending', -- pending|active|revoked|error
    hub_key_id         uuid,                        -- which hub key the site pinned
    api_version        text NOT NULL DEFAULT '',
    last_seen_at       timestamptz,
    link_state         text NOT NULL DEFAULT 'down', -- up|down
    lag_seconds        int  NOT NULL DEFAULT 0,
    created_by         uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

-- One-time pairing tokens, self-gating like the first-admin bootstrap: single-use
-- (used_at set) and time-limited. Only the hash is stored.
CREATE TABLE IF NOT EXISTS federation_join_tokens (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash      bytea NOT NULL,
    site_name       text NOT NULL,
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz,
    used_by_site_id uuid,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- Hub federation identity keys (Ed25519). Private key encrypted at rest via the
-- same secretbox envelope as the CA key. Supports dual-publish rotation.
CREATE TABLE IF NOT EXISTS federation_hub_keys (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    public_key      bytea NOT NULL,
    private_key_enc bytea NOT NULL,
    fingerprint     text NOT NULL,
    active          bool NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    retired_at      timestamptz
);

-- ---------------------------------------------------------------------------
-- Site-side control (in each site's own DB)
-- ---------------------------------------------------------------------------

-- Singleton row describing the hub this site is joined to and this site's own
-- identity keypair. id is pinned to 1 so there is at most one row.
CREATE TABLE IF NOT EXISTS federation_hub (
    id                   int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    hub_url              text NOT NULL,
    hub_public_key       bytea NOT NULL,
    hub_fingerprint      text NOT NULL,
    site_id              uuid NOT NULL,
    site_public_key      bytea NOT NULL,
    site_private_key_enc bytea NOT NULL,
    managed_mode         bool NOT NULL DEFAULT true,
    joined_at            timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

-- Stable site-local identity for a hub user, so FK-bearing rows (audit/sessions)
-- have a real local actor to reference when the hub acts on the site.
CREATE TABLE IF NOT EXISTS federation_shadow_users (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hub_user_id uuid NOT NULL UNIQUE,
    hub_username text NOT NULL,
    last_seen   timestamptz NOT NULL DEFAULT now()
);

-- Replay defense: nonces from hub-signed assertions the site has already honored.
CREATE TABLE IF NOT EXISTS federation_seen_nonces (
    nonce      text PRIMARY KEY,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fed_seen_nonces_exp ON federation_seen_nonces(expires_at);

-- ---------------------------------------------------------------------------
-- Hub read-model (cached aggregation). Every row carries site_id; entity IDs are
-- the site's native UUIDs (never re-keyed) so the PK is composite (site_id, id).
-- The `data` JSONB is an opaque snapshot of the site's row for display only.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fed_cache_hosts (
    site_id    uuid NOT NULL,
    host_id    uuid NOT NULL,
    data       jsonb NOT NULL,
    status     text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_id, host_id)
);

CREATE TABLE IF NOT EXISTS fed_cache_host_status_stats (
    site_id    uuid PRIMARY KEY,
    online     int NOT NULL DEFAULT 0,
    offline    int NOT NULL DEFAULT 0,
    unknown    int NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fed_cache_sessions (
    site_id    uuid NOT NULL,
    session_id uuid NOT NULL,
    data       jsonb NOT NULL,
    started_at timestamptz,
    ended_at   timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_id, session_id)
);

-- Audit is mirrored for display only. seq/hash are the SITE's chain fields kept
-- opaque here; the hub NEVER re-chains or merges. Verification runs at the site.
CREATE TABLE IF NOT EXISTS fed_cache_audit_summary (
    site_id    uuid NOT NULL,
    event_id   uuid NOT NULL,
    data       jsonb NOT NULL,
    seq        bigint,
    hash       text,
    created_at timestamptz,
    PRIMARY KEY (site_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_fed_audit_site_created ON fed_cache_audit_summary(site_id, created_at DESC);

CREATE TABLE IF NOT EXISTS fed_cache_scans (
    site_id    uuid NOT NULL,
    item_id    uuid NOT NULL,
    data       jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_id, item_id)
);

CREATE TABLE IF NOT EXISTS fed_cache_schedules (
    site_id    uuid NOT NULL,
    item_id    uuid NOT NULL,
    data       jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_id, item_id)
);

CREATE TABLE IF NOT EXISTS fed_cache_playbook_runs (
    site_id    uuid NOT NULL,
    item_id    uuid NOT NULL,
    data       jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_id, item_id)
);

CREATE TABLE IF NOT EXISTS fed_cache_sftp_transfers (
    site_id    uuid NOT NULL,
    item_id    uuid NOT NULL,
    data       jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_id, item_id)
);

-- Per-site, per-stream sync cursor + freshness, driving reconnect and the "stale
-- since HH:MM" badge in the hub UI.
CREATE TABLE IF NOT EXISTS fed_site_sync_state (
    site_id        uuid NOT NULL,
    stream         text NOT NULL,      -- hosts|sessions|audit|scans|...
    cursor         text NOT NULL DEFAULT '',
    last_synced_at timestamptz,
    lag_seconds    int NOT NULL DEFAULT 0,
    PRIMARY KEY (site_id, stream)
);
