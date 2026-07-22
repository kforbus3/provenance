package federation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/federation/fedauth"
	"github.com/fleet-terminal/backend/internal/federation/keys"
	fedlink "github.com/fleet-terminal/backend/internal/federation/link"
	"github.com/fleet-terminal/backend/internal/store"
)

// siteState is the resolved site identity + hub trust, loaded from federation_hub.
type siteState struct {
	siteID uuid.UUID
	priv   ed25519.PrivateKey
	hubPub ed25519.PublicKey
	hubURL string
}

// runSiteLink maintains the outbound control channel to the hub, joining on first
// run and reconnecting with backoff.
func (s *Service) runSiteLink(ctx context.Context) {
	backoff := 2 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		st, err := s.ensureJoined(ctx)
		if err != nil {
			s.log.Warn("federation: not joined", "err", err)
			sleep(ctx, 30*time.Second)
			continue
		}
		if err := s.connectAndServe(ctx, st); err != nil {
			s.log.Warn("federation link dropped", "err", err)
		}
		if sleep(ctx, backoff) {
			return
		}
		if backoff < 60*time.Second {
			backoff *= 2
		}
	}
}

// ensureJoined returns the site identity, performing a one-time join if needed.
func (s *Service) ensureJoined(ctx context.Context) (*siteState, error) {
	hub, err := s.deps.Store.GetFederationHub(ctx)
	if err == nil {
		priv, perr := keys.OpenPrivate(s.deps.Cfg.CAKeyPassphrase, hub.SitePrivateKeyEnc)
		if perr != nil {
			return nil, perr
		}
		pub, perr := keys.PublicFromBytes(hub.HubPublicKey)
		if perr != nil {
			return nil, perr
		}
		return &siteState{siteID: hub.SiteID, priv: priv, hubPub: pub, hubURL: hub.HubURL}, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if s.deps.Cfg.HubJoinToken == "" {
		return nil, errors.New("no hub join token configured for first join")
	}
	return s.join(ctx)
}

// join performs the one-time pairing handshake with the hub.
func (s *Service) join(ctx context.Context) (*siteState, error) {
	id, err := keys.Generate()
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(joinReq{
		JoinToken:     s.deps.Cfg.HubJoinToken,
		SitePublicKey: base64.StdEncoding.EncodeToString(id.Public),
		SiteName:      s.deps.Cfg.PublicURL,
		APIVersion:    "v1",
	})
	joinURL := httpBase(s.deps.Cfg.HubURL) + "/federation/join"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, joinURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("join request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return nil, fmt.Errorf("join rejected (%d): %s", resp.StatusCode, string(b))
	}
	var jr joinResp
	if err := json.NewDecoder(resp.Body).Decode(&jr); err != nil {
		return nil, err
	}
	// Pin the hub key: if a fingerprint was configured, it must match (MITM defense).
	if fp := s.deps.Cfg.HubKeyFingerprint; fp != "" && fp != jr.HubFingerprint {
		return nil, fmt.Errorf("hub key fingerprint mismatch: pinned %q got %q", fp, jr.HubFingerprint)
	}
	hubPubBytes, err := base64.StdEncoding.DecodeString(jr.HubPublicKey)
	if err != nil {
		return nil, err
	}
	siteID, err := uuid.Parse(jr.SiteID)
	if err != nil {
		return nil, err
	}
	sealed, err := keys.SealPrivate(s.deps.Cfg.CAKeyPassphrase, id.Private)
	if err != nil {
		return nil, err
	}
	if err := s.deps.Store.SaveFederationHub(ctx, &store.FederationHub{
		HubURL: s.deps.Cfg.HubURL, HubPublicKey: hubPubBytes, HubFingerprint: jr.HubFingerprint,
		SiteID: siteID, SitePublicKey: id.Public, SitePrivateKeyEnc: sealed, ManagedMode: true,
	}); err != nil {
		return nil, err
	}
	s.log.Info("joined hub", "site", siteID, "hubFingerprint", jr.HubFingerprint)
	hubPub, _ := keys.PublicFromBytes(hubPubBytes)
	return &siteState{siteID: siteID, priv: id.Private, hubPub: hubPub, hubURL: s.deps.Cfg.HubURL}, nil
}

// connectAndServe dials the hub link and runs push + heartbeat until it drops.
func (s *Service) connectAndServe(ctx context.Context, st *siteState) error {
	nonce, _ := randToken(12)
	token, err := fedauth.IssueLinkToken(st.siteID.String(), nonce, st.priv, 5*time.Minute, time.Now())
	if err != nil {
		return err
	}
	u := wsBase(st.hubURL) + "/federation/link?site=" + url.QueryEscape(st.siteID.String()) +
		"&token=" + url.QueryEscape(token)
	ws, resp, err := websocket.DefaultDialer.DialContext(ctx, u, nil)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("dial hub link (%d): %w", resp.StatusCode, err)
		}
		return fmt.Errorf("dial hub link: %w", err)
	}
	sess, err := fedlink.Wrap(st.siteID, ws, false)
	if err != nil {
		_ = ws.Close()
		return err
	}
	defer sess.Close()
	s.log.Info("linked to hub", "site", st.siteID)

	linkCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.acceptHubStreams(linkCtx, sess) // hub-initiated proxy streams (F3/F4)
	return s.pushLoop(linkCtx, sess)     // blocks; returns on error/close
}

// pushLoop opens a push stream and streams host snapshots + heartbeats.
func (s *Service) pushLoop(ctx context.Context, sess *fedlink.Session) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()
	if err := WriteFrame(stream, &Frame{Kind: "push"}); err != nil {
		return err
	}
	enc := json.NewEncoder(stream)

	send := func() error {
		hosts, err := s.deps.Store.ListHosts(ctx, 1000, 0)
		if err != nil {
			return nil // transient; try again next tick
		}
		for i := range hosts {
			h := hosts[i]
			status := ""
			if h.Status != nil {
				status = h.Status.Status
			}
			raw, _ := json.Marshal(h)
			data, _ := json.Marshal(hostPush{HostID: h.ID, Status: status, Data: raw})
			if err := enc.Encode(PushMsg{Type: "host", Data: data}); err != nil {
				return err
			}
		}
		return enc.Encode(PushMsg{Type: "heartbeat", Data: json.RawMessage(`{}`)})
	}

	if err := send(); err != nil {
		return err
	}
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := send(); err != nil {
				return err
			}
		}
	}
}

// acceptHubStreams handles hub-initiated proxy streams. The verify/inject/dispatch
// path is Phase F3/F4; for now unknown streams are drained and closed so the link
// stays healthy.
func (s *Service) acceptHubStreams(ctx context.Context, sess *fedlink.Session) {
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go func() {
			defer stream.Close()
			f, br, err := ReadFrame(stream)
			if err != nil {
				return
			}
			s.serveHubStream(ctx, f, br, stream)
		}()
	}
}

// handleLeave drops the hub link and returns the site to standalone-like behavior
// (managed mode off) until re-joined.
func (s *Service) handleLeave(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	if err := s.deps.Store.DeleteFederationHub(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not leave hub")
		return
	}
	var actorID *uuid.UUID
	if p != nil {
		actorID = &p.UserID
	}
	s.audit(r.Context(), actorID, actorName(p), "federation.left_hub", "", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "left"})
}

// --- url helpers ---

func normalizeBase(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// Fall back: treat as host only.
		return &url.URL{Scheme: "https", Host: raw}
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}
}

func httpBase(raw string) string {
	u := normalizeBase(raw)
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss", "":
		u.Scheme = "https"
	}
	return u.String()
}

func wsBase(raw string) string {
	u := normalizeBase(raw)
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https", "":
		u.Scheme = "wss"
	}
	return u.String()
}

func sleep(ctx context.Context, d time.Duration) (cancelled bool) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-t.C:
		return false
	}
}
