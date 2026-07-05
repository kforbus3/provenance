package federation

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/federation/fedauth"
	"github.com/fleet-terminal/backend/internal/federation/keys"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/terminal"
)

// serveHubStream dispatches a hub-initiated proxy stream on the site: it verifies
// the hub's service token + acting-user assertion against the pinned hub key,
// synthesizes an auth.Principal from the assertion, and either serves the request
// through the site's own router (http/sftp) or drives the terminal relay (ws).
func (s *Service) serveHubStream(ctx context.Context, f *Frame, body *bufio.Reader, stream io.ReadWriteCloser) {
	switch f.Kind {
	case "http", "sftp":
		s.serveHubHTTP(ctx, f, body, stream)
	case "ws":
		s.serveHubWS(ctx, f, body, stream)
	case "hubkey":
		s.applyHubKey(ctx, body)
	default:
		_, _ = io.Copy(io.Discard, body)
	}
}

// applyHubKey updates the site's stored hub public key when the hub rotates and
// pushes the new key over the link, so subsequent hub-signed tokens verify.
func (s *Service) applyHubKey(ctx context.Context, body io.Reader) {
	var msg struct {
		PublicKey   string `json:"publicKey"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(body).Decode(&msg); err != nil {
		return
	}
	pub, err := base64.StdEncoding.DecodeString(msg.PublicKey)
	if err != nil || len(pub) == 0 {
		return
	}
	if err := s.deps.Store.UpdateFederationHubKey(ctx, pub, msg.Fingerprint); err != nil {
		s.log.Warn("apply rotated hub key", "err", err)
		return
	}
	s.log.Info("applied rotated hub key", "fingerprint", msg.Fingerprint)
}

// verifyAssertion authenticates a hub-proxied request: it checks managed mode, the
// hub service token, and the acting-user assertion (bound to this exact
// method+path+body, single-use nonce), then synthesizes the acting principal.
func (s *Service) verifyAssertion(ctx context.Context, f *Frame, reqBody []byte) (*auth.Principal, bool) {
	hub, err := s.deps.Store.GetFederationHub(ctx)
	if err != nil || !hub.ManagedMode {
		return nil, false
	}
	hubPub, err := keys.PublicFromBytes(hub.HubPublicKey)
	if err != nil {
		return nil, false
	}
	svc, err := fedauth.ParseServiceToken(f.ServiceToken, hubPub)
	if err != nil || svc.SiteID != hub.SiteID.String() {
		return nil, false
	}
	assertion, err := fedauth.ParseAssertion(f.ActorAssertion, hubPub)
	if err != nil || assertion.SiteID != hub.SiteID.String() {
		return nil, false
	}
	if assertion.RequestDigest != fedauth.RequestDigest(f.Method, f.Path, reqBody) {
		return nil, false
	}
	fresh, err := s.deps.Store.UseNonce(ctx, assertion.Nonce, time.Now().Add(2*time.Minute))
	if err != nil || !fresh {
		return nil, false
	}
	hubUserID, _ := uuid.Parse(assertion.HubUserID)
	shadowID, err := s.deps.Store.UpsertShadowUser(ctx, hubUserID, assertion.HubUsername)
	if err != nil {
		return nil, false
	}
	perms := map[string]bool{}
	super := assertion.SuperAdmin
	for _, p := range assertion.Permissions {
		if p == "*" {
			super = true
			continue
		}
		perms[p] = true
	}
	return &auth.Principal{
		UserID: shadowID, SessionID: uuid.Nil,
		Username: "hub:" + assertion.HubUsername, IsSuperAdmin: super, Permissions: perms,
	}, true
}

func (s *Service) serveHubHTTP(ctx context.Context, f *Frame, body *bufio.Reader, stream io.ReadWriteCloser) {
	if s.siteHandler == nil {
		_ = WriteRespHeader(stream, &RespHeader{Status: 503, Error: "site handler not ready"})
		return
	}
	// Read exactly the request body the hub declared, then verify.
	reqBody := make([]byte, f.BodyLen)
	if f.BodyLen > 0 {
		if _, err := io.ReadFull(body, reqBody); err != nil {
			_ = WriteRespHeader(stream, &RespHeader{Status: 400, Error: "short body"})
			return
		}
	}
	principal, ok := s.verifyAssertion(ctx, f, reqBody)
	if !ok {
		_ = WriteRespHeader(stream, &RespHeader{Status: 401, Error: "federation authorization failed"})
		return
	}

	target := f.Path
	if f.Query != "" {
		target += "?" + f.Query
	}
	req := httptest.NewRequest(f.Method, target, bytes.NewReader(reqBody))
	if ct := f.Header["Content-Type"]; ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req = req.WithContext(auth.WithFederatedPrincipal(ctx, principal))
	// Stream the response straight onto the tunnel stream (no buffering), so large
	// SFTP downloads/tars don't materialize in memory on either side.
	srw := newStreamRW(stream)
	s.siteHandler.ServeHTTP(srw, req)
	srw.finish()
}

// serveHubWS runs a hub-proxied terminal on the site: verify the assertion, then
// drive the site's own terminal relay with the tunnel stream as its transport.
func (s *Service) serveHubWS(ctx context.Context, f *Frame, body *bufio.Reader, stream io.ReadWriteCloser) {
	principal, ok := s.verifyAssertion(ctx, f, nil)
	if !ok {
		_ = writeWSMessage(stream, msgText, []byte(`{"type":"error","data":"federation authorization failed"}`))
		return
	}
	host, ok := s.resolveHost(ctx, f.Path)
	if !ok {
		_ = writeWSMessage(stream, msgText, []byte(`{"type":"error","data":"host not found"}`))
		return
	}
	if s.gw == nil {
		_ = writeWSMessage(stream, msgText, []byte(`{"type":"error","data":"site gateway unavailable"}`))
		return
	}
	transport := &streamWSTransport{r: body, w: stream, c: stream}
	terminal.ServeFederated(s.deps, s.gw, ctx, transport, principal, host, "federation")
}

// resolveHost extracts a host id from a /api/v1/terminal/{hostId} path and loads it.
func (s *Service) resolveHost(ctx context.Context, path string) (*models.Host, bool) {
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return nil, false
	}
	id, err := uuid.Parse(path[idx+1:])
	if err != nil {
		return nil, false
	}
	host, err := s.deps.Store.GetHost(ctx, id)
	if err != nil {
		return nil, false
	}
	return host, true
}
