package federation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/federation/fedauth"
	"github.com/fleet-terminal/backend/internal/federation/keys"
	fedlink "github.com/fleet-terminal/backend/internal/federation/link"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
	"github.com/fleet-terminal/backend/internal/tenant"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  32 << 10,
	WriteBufferSize: 32 << 10,
	// The link is authenticated by a site-signed token, not by Origin.
	CheckOrigin: func(*http.Request) bool { return true },
}

// ensureHubKey loads the active hub federation identity or generates one.
func (s *Service) ensureHubKey(ctx context.Context) error {
	k, err := s.deps.Store.ActiveHubKey(ctx)
	if err == nil {
		priv, perr := keys.OpenPrivate(s.deps.Cfg.CAKeyPassphrase, k.PrivateKeyEnc)
		if perr != nil {
			return perr
		}
		pub, perr := keys.PublicFromBytes(k.PublicKey)
		if perr != nil {
			return perr
		}
		s.hubKeyID, s.hubPriv, s.hubPub, s.hubFinger = k.ID.String(), priv, pub, k.Fingerprint
		return nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	id, err := keys.Generate()
	if err != nil {
		return err
	}
	sealed, err := keys.SealPrivate(s.deps.Cfg.CAKeyPassphrase, id.Private)
	if err != nil {
		return err
	}
	rec, err := s.deps.Store.CreateHubKey(ctx, id.Public, sealed, id.Fingerprint)
	if err != nil {
		return err
	}
	s.hubKeyID, s.hubPriv, s.hubPub, s.hubFinger = rec.ID.String(), id.Private, id.Public, id.Fingerprint
	s.log.Info("generated hub federation identity", "fingerprint", id.Fingerprint)
	return nil
}

// --- site-facing: join ---

type joinReq struct {
	JoinToken     string `json:"joinToken"`
	SitePublicKey string `json:"sitePublicKey"` // base64 std
	SiteName      string `json:"siteName"`
	APIVersion    string `json:"apiVersion"`
}

type joinResp struct {
	SiteID         string `json:"siteId"`
	HubPublicKey   string `json:"hubPublicKey"`
	HubFingerprint string `json:"hubFingerprint"`
}

func (s *Service) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req joinReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	pub, err := base64.StdEncoding.DecodeString(req.SitePublicKey)
	if err != nil || len(pub) == 0 {
		writeErr(w, http.StatusBadRequest, "bad site public key")
		return
	}
	siteID := uuid.New()
	// The join endpoint is site-facing (no operator session), so it runs under
	// bypass; the site inherits the hub tenant of the operator who minted the token.
	bctx := tenant.WithBypass(r.Context())
	tok, err := s.deps.Store.ConsumeJoinToken(bctx, hashToken(req.JoinToken), siteID, time.Now())
	if err != nil {
		writeErr(w, http.StatusForbidden, "invalid or expired join token")
		return
	}
	name := tok.SiteName
	if name == "" {
		name = req.SiteName
	}
	hubKeyID, _ := uuid.Parse(s.hubKeyID)
	if _, err := s.deps.Store.CreateSite(bctx, &store.FederationSite{
		ID: siteID, Name: name, PublicKey: pub, Status: "pending",
		HubKeyID: &hubKeyID, APIVersion: req.APIVersion,
	}, nil, tok.TenantID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not register site")
		return
	}
	s.audit(r.Context(), nil, "site:"+name, "federation.site_joined", siteID.String(),
		map[string]any{"name": name})
	writeJSON(w, http.StatusOK, joinResp{
		SiteID:         siteID.String(),
		HubPublicKey:   base64.StdEncoding.EncodeToString(s.hubPub),
		HubFingerprint: s.hubFinger,
	})
}

// --- site-facing: persistent link ---

func (s *Service) handleLink(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(r.URL.Query().Get("site"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad site id")
		return
	}
	// Site-facing link: no operator session, so all site/cache DB access runs under
	// bypass with the site's own tenant supplied explicitly (site-as-tenant).
	bctx := tenant.WithBypass(r.Context())
	site, err := s.deps.Store.GetSite(bctx, siteID)
	if err != nil || site.Status == "revoked" {
		writeErr(w, http.StatusForbidden, "unknown or revoked site")
		return
	}
	pub, err := keys.PublicFromBytes(site.PublicKey)
	if err != nil {
		writeErr(w, http.StatusForbidden, "bad site key")
		return
	}
	if _, err := fedauth.ParseLinkToken(r.URL.Query().Get("token"), pub); err != nil {
		writeErr(w, http.StatusUnauthorized, "bad link token")
		return
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	sess, err := fedlink.Wrap(siteID, ws, true)
	if err != nil {
		_ = ws.Close()
		return
	}
	s.registry.Put(sess)
	_ = s.deps.Store.SetSiteStatus(bctx, siteID, "active")
	_ = s.deps.Store.SetSiteLink(bctx, siteID, "up", 0, time.Now())
	// Push the current hub key so a site that reconnected after a hub-key rotation
	// re-learns it before any proxied request arrives.
	go func() { _ = s.pushHubKey(sess) }()
	s.log.Info("site linked", "site", siteID, "name", site.Name)

	s.serveSite(bctx, sess, site.TenantID) // blocks until the link drops

	s.registry.Remove(siteID)
	_ = s.deps.Store.SetSiteLink(tenant.WithBypass(context.Background()), siteID, "down", 0, time.Now())
	s.log.Info("site link closed", "site", siteID)
}

// serveSite accepts streams the site opens (read-model push, heartbeat) until the
// session closes.
func (s *Service) serveSite(ctx context.Context, sess *fedlink.Session, siteTenant uuid.UUID) {
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go s.handleSiteStream(ctx, sess.SiteID, siteTenant, stream)
	}
}

func (s *Service) handleSiteStream(ctx context.Context, siteID, siteTenant uuid.UUID, stream io.ReadWriteCloser) {
	defer stream.Close()
	f, br, err := ReadFrame(stream)
	if err != nil {
		return
	}
	switch f.Kind {
	case "push":
		s.ingestPush(ctx, siteID, siteTenant, br)
	case "ping":
		_ = s.deps.Store.SetSiteLink(ctx, siteID, "up", 0, time.Now())
	}
}

// handleRotateKey generates a new hub federation identity, retires the previous
// one (kept for verification overlap), and pushes the new public key to every
// currently-linked site so their verification stays current with no downtime.
// Sites that are offline re-learn the key when they next link (pushHubKey runs on
// every link).
func (s *Service) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	id, err := keys.Generate()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "keygen failed")
		return
	}
	sealed, err := keys.SealPrivate(s.deps.Cfg.CAKeyPassphrase, id.Private)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "seal failed")
		return
	}
	rec, err := s.deps.Store.CreateHubKey(r.Context(), id.Public, sealed, id.Fingerprint)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store key failed")
		return
	}
	if err := s.deps.Store.RetireHubKeysExcept(r.Context(), rec.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "retire failed")
		return
	}
	// Switch signing to the new key.
	s.hubKeyID, s.hubPriv, s.hubPub, s.hubFinger = rec.ID.String(), id.Private, id.Public, id.Fingerprint
	// Push to every live site so verification stays current.
	pushed := 0
	for _, siteID := range s.registry.SiteIDs() {
		if sess, ok := s.registry.Get(siteID); ok {
			if s.pushHubKey(sess) == nil {
				pushed++
			}
		}
	}
	var actorID *uuid.UUID
	if p != nil {
		actorID = &p.UserID
	}
	s.audit(r.Context(), actorID, actorName(p), "federation.hub_key_rotated", "",
		map[string]any{"fingerprint": id.Fingerprint, "pushedToSites": pushed})
	writeJSON(w, http.StatusOK, map[string]any{"fingerprint": id.Fingerprint, "pushedToSites": pushed})
}

// pushHubKey sends the current hub public key + fingerprint to a linked site over
// a control stream, so the site trusts tokens signed by the (possibly rotated)
// active hub key.
func (s *Service) pushHubKey(sess *fedlink.Session) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()
	if err := WriteFrame(stream, &Frame{Kind: "hubkey"}); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{
		"publicKey":   base64.StdEncoding.EncodeToString(s.hubPub),
		"fingerprint": s.hubFinger,
	})
	_, err = stream.Write(body)
	return err
}

// --- operator-facing management ---

func (s *Service) handleListSites(w http.ResponseWriter, r *http.Request) {
	sites, err := s.deps.Store.ListSites(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list sites")
		return
	}
	// Reflect live link state from the in-memory registry (authoritative for "up").
	live := map[uuid.UUID]bool{}
	for _, id := range s.registry.SiteIDs() {
		live[id] = true
	}
	for _, st := range sites {
		if live[st.ID] {
			st.LinkState = "up"
		} else if st.LinkState == "up" {
			st.LinkState = "down"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sites": sites, "count": len(sites)})
}

type createTokenReq struct {
	SiteName string `json:"siteName"`
	TTLHours int    `json:"ttlHours"`
}

func (s *Service) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	var req createTokenReq
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&req)
	if req.SiteName == "" {
		writeErr(w, http.StatusBadRequest, "siteName is required")
		return
	}
	ttl := time.Duration(req.TTLHours) * time.Hour
	if ttl <= 0 {
		ttl = time.Hour
	}
	tok, err := randToken(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token error")
		return
	}
	var createdBy *uuid.UUID
	if p != nil {
		createdBy = &p.UserID
	}
	if _, err := s.deps.Store.CreateJoinToken(r.Context(), hashToken(tok), req.SiteName, time.Now().Add(ttl), createdBy); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create token")
		return
	}
	s.audit(r.Context(), createdBy, actorName(p), "federation.token_created", "", map[string]any{"siteName": req.SiteName})
	// Return the plaintext token + the config blob the operator pastes at the site.
	writeJSON(w, http.StatusCreated, map[string]any{
		"joinToken":      tok,
		"hubFingerprint": s.hubFinger,
		"env": map[string]string{
			"FLEET_MODE":                 "site",
			"FLEET_HUB_URL":              s.deps.Cfg.PublicURL,
			"FLEET_HUB_JOIN_TOKEN":       tok,
			"FLEET_HUB_KEY_FINGERPRINT":  s.hubFinger,
			"FLEET_FEDERATION_TRANSPORT": "wss",
		},
	})
}

func (s *Service) handleRevokeSite(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	id, err := uuid.Parse(chi.URLParam(r, "siteId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad site id")
		return
	}
	_ = s.deps.Store.SetSiteStatus(r.Context(), id, "revoked")
	s.registry.Remove(id)
	if err := s.deps.Store.DeleteSite(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not remove site")
		return
	}
	var actorID *uuid.UUID
	if p != nil {
		actorID = &p.UserID
	}
	s.audit(r.Context(), actorID, actorName(p), "federation.site_revoked", id.String(), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// handleCacheHosts returns the aggregated host read-model with composite ids.
func (s *Service) handleCacheHosts(w http.ResponseWriter, r *http.Request) {
	var siteFilter *uuid.UUID
	if q := r.URL.Query().Get("site"); q != "" {
		if id, err := uuid.Parse(q); err == nil {
			siteFilter = &id
		}
	}
	rows, err := s.deps.Store.ListCacheHosts(r.Context(), siteFilter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not read cache")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, h := range rows {
		out = append(out, map[string]any{
			"federatedId": h.SiteID.String() + ":" + h.HostID.String(),
			"siteId":      h.SiteID.String(),
			"hostId":      h.HostID.String(),
			"status":      h.Status,
			"host":        json.RawMessage(h.Data),
			"cachedAt":    h.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": out, "count": len(out)})
}

// --- helpers ---

func (s *Service) audit(ctx context.Context, actorID *uuid.UUID, actorName, action, targetID string, detail map[string]any) {
	_, _ = s.deps.Store.AppendAudit(ctx, models.AuditEvent{
		ActorID: actorID, ActorName: actorName, Action: action,
		TargetKind: "federation", TargetID: targetID, Detail: detail,
	})
}

func actorName(p *auth.Principal) string {
	if p == nil {
		return ""
	}
	return p.Username
}
