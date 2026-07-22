package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// FederationSite is a remote site registered on this hub.
type FederationSite struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	PublicKey        []byte     `json:"-"`
	PendingPublicKey []byte     `json:"-"`
	Status           string     `json:"status"`
	HubKeyID         *uuid.UUID `json:"-"`
	APIVersion       string     `json:"apiVersion"`
	LastSeenAt       *time.Time `json:"lastSeenAt,omitempty"`
	LinkState        string     `json:"linkState"`
	LagSeconds       int        `json:"lagSeconds"`
	TenantID         uuid.UUID  `json:"-"` // hub tenant this site belongs to (site-as-tenant)
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
}

// FederationJoinToken is a one-time pairing token (hub side).
type FederationJoinToken struct {
	ID        uuid.UUID
	SiteName  string
	ExpiresAt time.Time
	UsedAt    *time.Time
	// TenantID is the hub tenant the minting operator was scoped to; the joining
	// site inherits it (site-as-tenant).
	TenantID uuid.UUID
}

// FederationHubKey is a hub federation identity key.
type FederationHubKey struct {
	ID            uuid.UUID
	PublicKey     []byte
	PrivateKeyEnc []byte
	Fingerprint   string
	Active        bool
	CreatedAt     time.Time
}

// FederationHub is the site-side singleton describing the joined hub + this
// site's own identity.
type FederationHub struct {
	HubURL            string
	HubPublicKey      []byte
	HubFingerprint    string
	SiteID            uuid.UUID
	SitePublicKey     []byte
	SitePrivateKeyEnc []byte
	ManagedMode       bool
	JoinedAt          time.Time
}

// ---------------------------------------------------------------------------
// Hub: sites
// ---------------------------------------------------------------------------

const fedSiteCols = `id, name, public_key, pending_public_key, status, hub_key_id,
	api_version, last_seen_at, link_state, lag_seconds, tenant_id, created_at, updated_at`

func scanSite(row interface{ Scan(...any) error }) (*FederationSite, error) {
	var s FederationSite
	if err := row.Scan(&s.ID, &s.Name, &s.PublicKey, &s.PendingPublicKey, &s.Status,
		&s.HubKeyID, &s.APIVersion, &s.LastSeenAt, &s.LinkState, &s.LagSeconds,
		&s.TenantID, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, err
	}
	return &s, nil
}

// CreateSite registers a newly-joined site under the given hub tenant (from the join
// token). tenant_id is set explicitly because join runs outside a tenant-scoped
// request context (see internal/federation handleJoin).
func (s *Store) CreateSite(ctx context.Context, site *FederationSite, createdBy *uuid.UUID, tenantID uuid.UUID) (*FederationSite, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO federation_sites(id, name, public_key, status, hub_key_id, api_version, created_by, tenant_id)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+fedSiteCols,
		site.ID, site.Name, site.PublicKey, nz(site.Status, "pending"), site.HubKeyID, site.APIVersion, createdBy, tenantID)
	return scanSite(row)
}

func (s *Store) GetSite(ctx context.Context, id uuid.UUID) (*FederationSite, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+fedSiteCols+` FROM federation_sites WHERE id=$1`, id)
	site, err := scanSite(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return site, nil
}

func (s *Store) ListSites(ctx context.Context) ([]*FederationSite, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+fedSiteCols+` FROM federation_sites ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*FederationSite
	for rows.Next() {
		site, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, site)
	}
	return out, rows.Err()
}

// SetSiteStatus updates a site's lifecycle status.
func (s *Store) SetSiteStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE federation_sites SET status=$2, updated_at=now() WHERE id=$1`, id, status)
	return err
}

// SetSiteLink records link liveness (heartbeat).
func (s *Store) SetSiteLink(ctx context.Context, id uuid.UUID, linkState string, lagSeconds int, seenAt time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE federation_sites SET link_state=$2, lag_seconds=$3, last_seen_at=$4, updated_at=now()
		 WHERE id=$1`, id, linkState, lagSeconds, seenAt)
	return err
}

// SetSitePendingKey stages a site-proposed new public key. The site rotates its
// own identity by signing the new key with its current key over the live link;
// the hub records it here (leaving the active key in force) and promotes it on
// the site's next reconnect with the new key — so there is no window in which the
// link cannot be re-established. Site-initiated key rotation (mirror of the hub's).
func (s *Store) SetSitePendingKey(ctx context.Context, id uuid.UUID, pendingPub []byte) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE federation_sites SET pending_public_key=$2, updated_at=now() WHERE id=$1`, id, pendingPub)
	return err
}

// PromoteSitePendingKey makes the staged key the active key and clears the
// pending slot. Called when a site first authenticates with its rotated key.
func (s *Store) PromoteSitePendingKey(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE federation_sites SET public_key=pending_public_key, pending_public_key=NULL, updated_at=now()
		 WHERE id=$1 AND pending_public_key IS NOT NULL`, id)
	return err
}

// ---------------------------------------------------------------------------
// Hub: join tokens (self-gating, single-use)
// ---------------------------------------------------------------------------

func (s *Store) CreateJoinToken(ctx context.Context, tokenHash []byte, siteName string, expiresAt time.Time, createdBy *uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx,
		`INSERT INTO federation_join_tokens(token_hash, site_name, expires_at, created_by)
		 VALUES($1,$2,$3,$4) RETURNING id`, tokenHash, siteName, expiresAt, createdBy).Scan(&id)
	return id, err
}

// ConsumeJoinToken atomically validates and marks a token used, returning it.
// Returns ErrNotFound if the token is unknown, expired, or already used.
func (s *Store) ConsumeJoinToken(ctx context.Context, tokenHash []byte, bySiteID uuid.UUID, now time.Time) (*FederationJoinToken, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE federation_join_tokens
		 SET used_at=$3, used_by_site_id=$4
		 WHERE token_hash=$1 AND used_at IS NULL AND expires_at > $2
		 RETURNING id, site_name, expires_at, used_at, tenant_id`, tokenHash, now, now, bySiteID)
	var t FederationJoinToken
	if err := row.Scan(&t.ID, &t.SiteName, &t.ExpiresAt, &t.UsedAt, &t.TenantID); err != nil {
		return nil, mapNotFound(err)
	}
	return &t, nil
}

// ---------------------------------------------------------------------------
// Hub: identity keys
// ---------------------------------------------------------------------------

func (s *Store) CreateHubKey(ctx context.Context, pub, privEnc []byte, fingerprint string) (*FederationHubKey, error) {
	var k FederationHubKey
	err := s.pool.QueryRow(ctx,
		`INSERT INTO federation_hub_keys(public_key, private_key_enc, fingerprint)
		 VALUES($1,$2,$3) RETURNING id, public_key, private_key_enc, fingerprint, active, created_at`,
		pub, privEnc, fingerprint).Scan(&k.ID, &k.PublicKey, &k.PrivateKeyEnc, &k.Fingerprint, &k.Active, &k.CreatedAt)
	return &k, err
}

// RetireHubKeysExcept marks every hub key except keepID inactive (retired). The
// retired rows are kept so tokens they signed still verify during the overlap.
func (s *Store) RetireHubKeysExcept(ctx context.Context, keepID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE federation_hub_keys SET active=false, retired_at=now()
		 WHERE id <> $1 AND active`, keepID)
	return err
}

func (s *Store) ActiveHubKey(ctx context.Context) (*FederationHubKey, error) {
	var k FederationHubKey
	err := s.pool.QueryRow(ctx,
		`SELECT id, public_key, private_key_enc, fingerprint, active, created_at
		 FROM federation_hub_keys WHERE active ORDER BY created_at DESC LIMIT 1`).
		Scan(&k.ID, &k.PublicKey, &k.PrivateKeyEnc, &k.Fingerprint, &k.Active, &k.CreatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &k, nil
}

// ---------------------------------------------------------------------------
// Site: hub record, shadow users, nonces
// ---------------------------------------------------------------------------

func (s *Store) SaveFederationHub(ctx context.Context, h *FederationHub) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO federation_hub(id, hub_url, hub_public_key, hub_fingerprint, site_id,
			site_public_key, site_private_key_enc, managed_mode)
		 VALUES(1,$1,$2,$3,$4,$5,$6,$7)
		 ON CONFLICT (id) DO UPDATE SET hub_url=EXCLUDED.hub_url, hub_public_key=EXCLUDED.hub_public_key,
			hub_fingerprint=EXCLUDED.hub_fingerprint, site_id=EXCLUDED.site_id,
			site_public_key=EXCLUDED.site_public_key, site_private_key_enc=EXCLUDED.site_private_key_enc,
			managed_mode=EXCLUDED.managed_mode, updated_at=now()`,
		h.HubURL, h.HubPublicKey, h.HubFingerprint, h.SiteID, h.SitePublicKey, h.SitePrivateKeyEnc, h.ManagedMode)
	return err
}

func (s *Store) GetFederationHub(ctx context.Context) (*FederationHub, error) {
	var h FederationHub
	err := s.pool.QueryRow(ctx,
		`SELECT hub_url, hub_public_key, hub_fingerprint, site_id, site_public_key,
			site_private_key_enc, managed_mode, joined_at FROM federation_hub WHERE id=1`).
		Scan(&h.HubURL, &h.HubPublicKey, &h.HubFingerprint, &h.SiteID, &h.SitePublicKey,
			&h.SitePrivateKeyEnc, &h.ManagedMode, &h.JoinedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &h, nil
}

func (s *Store) DeleteFederationHub(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM federation_hub WHERE id=1`)
	return err
}

// UpdateFederationHubKey updates the site's stored hub public key + fingerprint,
// applied when the hub rotates its identity and pushes the new key over the link.
func (s *Store) UpdateFederationHubKey(ctx context.Context, pub []byte, fingerprint string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE federation_hub SET hub_public_key=$1, hub_fingerprint=$2, updated_at=now() WHERE id=1`,
		pub, fingerprint)
	return err
}

// UpsertShadowUser maps a hub user to a stable site-local id.
func (s *Store) UpsertShadowUser(ctx context.Context, hubUserID uuid.UUID, hubUsername string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx,
		`INSERT INTO federation_shadow_users(hub_user_id, hub_username)
		 VALUES($1,$2)
		 ON CONFLICT (hub_user_id) DO UPDATE SET hub_username=EXCLUDED.hub_username, last_seen=now()
		 RETURNING id`, hubUserID, hubUsername).Scan(&id)
	return id, err
}

// UseNonce records a nonce; returns false if it was already seen (replay).
func (s *Store) UseNonce(ctx context.Context, nonce string, expiresAt time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO federation_seen_nonces(nonce, expires_at) VALUES($1,$2)
		 ON CONFLICT (nonce) DO NOTHING`, nonce, expiresAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// PruneNonces removes expired replay-defense nonces.
func (s *Store) PruneNonces(ctx context.Context, now time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM federation_seen_nonces WHERE expires_at < $1`, now)
	return err
}

// ---------------------------------------------------------------------------
// Hub: read-model cache
// ---------------------------------------------------------------------------

// UpsertCacheHost stores/updates a site's host snapshot. tenantID is the site's hub
// tenant, passed explicitly because ingest runs under bypass (background link).
func (s *Store) UpsertCacheHost(ctx context.Context, siteID, hostID uuid.UUID, status string, data json.RawMessage, tenantID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO fed_cache_hosts(site_id, host_id, data, status, updated_at, tenant_id)
		 VALUES($1,$2,$3,$4, now(), $5)
		 ON CONFLICT (site_id, host_id) DO UPDATE SET data=EXCLUDED.data, status=EXCLUDED.status, updated_at=now()`,
		siteID, hostID, data, nzp(status), tenantID)
	return err
}

// FedCacheHost is a cached host row with its owning site.
type FedCacheHost struct {
	SiteID    uuid.UUID       `json:"siteId"`
	HostID    uuid.UUID       `json:"hostId"`
	Status    string          `json:"status,omitempty"`
	Data      json.RawMessage `json:"data"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

// ListCacheHosts returns cached hosts, optionally filtered to one site.
func (s *Store) ListCacheHosts(ctx context.Context, siteID *uuid.UUID) ([]FedCacheHost, error) {
	q := `SELECT site_id, host_id, coalesce(status,''), data, updated_at FROM fed_cache_hosts`
	args := []any{}
	if siteID != nil {
		q += ` WHERE site_id=$1`
		args = append(args, *siteID)
	}
	q += ` ORDER BY updated_at DESC`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FedCacheHost
	for rows.Next() {
		var h FedCacheHost
		if err := rows.Scan(&h.SiteID, &h.HostID, &h.Status, &h.Data, &h.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// DeleteSiteCache clears all cached rows for a site (used on unjoin/revoke).
func (s *Store) DeleteSiteCache(ctx context.Context, siteID uuid.UUID) error {
	for _, t := range []string{"fed_cache_hosts", "fed_cache_host_status_stats", "fed_cache_sessions",
		"fed_cache_audit_summary", "fed_cache_scans", "fed_cache_schedules",
		"fed_cache_playbook_runs", "fed_cache_sftp_transfers", "fed_site_sync_state"} {
		if _, err := s.pool.Exec(ctx, `DELETE FROM `+t+` WHERE site_id=$1`, siteID); err != nil {
			return err
		}
	}
	return nil
}

// DeleteSite removes a site registration and its cache.
func (s *Store) DeleteSite(ctx context.Context, id uuid.UUID) error {
	if err := s.DeleteSiteCache(ctx, id); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM federation_sites WHERE id=$1`, id)
	return err
}

// UpsertGenericCache stores a snapshot into one of the generic per-site cache
// tables (fed_cache_scans/schedules/playbook_runs/sftp_transfers/sessions).
func (s *Store) UpsertGenericCache(ctx context.Context, table string, siteID, itemID uuid.UUID, data json.RawMessage, tenantID uuid.UUID) error {
	// table is a fixed internal constant chosen by the ingester, never user input.
	_, err := s.pool.Exec(ctx,
		`INSERT INTO `+table+`(site_id, item_id, data, updated_at, tenant_id) VALUES($1,$2,$3, now(), $4)
		 ON CONFLICT (site_id, item_id) DO UPDATE SET data=EXCLUDED.data, updated_at=now()`,
		siteID, itemID, data, tenantID)
	return err
}

// SetSyncState records a per-stream cursor + freshness for a site.
func (s *Store) SetSyncState(ctx context.Context, siteID uuid.UUID, stream, cursor string, lagSeconds int, at time.Time, tenantID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO fed_site_sync_state(site_id, stream, cursor, last_synced_at, lag_seconds, tenant_id)
		 VALUES($1,$2,$3,$4,$5,$6)
		 ON CONFLICT (site_id, stream) DO UPDATE SET cursor=EXCLUDED.cursor,
			last_synced_at=EXCLUDED.last_synced_at, lag_seconds=EXCLUDED.lag_seconds`,
		siteID, stream, cursor, at, lagSeconds, tenantID)
	return err
}

// --- small helpers ---

func nz(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func nzp(v string) any {
	if v == "" {
		return nil
	}
	return v
}
