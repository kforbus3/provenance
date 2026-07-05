package federation

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/federation/fedauth"
	"github.com/fleet-terminal/backend/internal/federation/keys"
)

// serveHubStream dispatches a hub-initiated proxy stream on the site: it verifies
// the hub's service token + acting-user assertion against the pinned hub key,
// synthesizes an auth.Principal from the assertion, and serves the request
// through the site's own router (unmodified handlers). WebSocket/streaming kinds
// (terminal/SFTP) are handled in F3.
func (s *Service) serveHubStream(ctx context.Context, f *Frame, body *bufio.Reader, stream io.ReadWriteCloser) {
	switch f.Kind {
	case "http":
		s.serveHubHTTP(ctx, f, body, stream)
	case "ws", "sftp":
		_ = WriteRespHeader(stream, &RespHeader{Status: 501, Error: "streaming proxy (F3) not yet implemented"})
	default:
		_, _ = io.Copy(io.Discard, body)
	}
}

func (s *Service) serveHubHTTP(ctx context.Context, f *Frame, body *bufio.Reader, stream io.ReadWriteCloser) {
	fail := func(status int, msg string) {
		_ = WriteRespHeader(stream, &RespHeader{Status: status, Error: msg})
	}
	if s.siteHandler == nil {
		fail(503, "site handler not ready")
		return
	}
	hub, err := s.deps.Store.GetFederationHub(ctx)
	if err != nil || !hub.ManagedMode {
		fail(403, "site not in managed mode")
		return
	}
	hubPub, err := keys.PublicFromBytes(hub.HubPublicKey)
	if err != nil {
		fail(500, "bad hub key")
		return
	}
	// Verify the hub service token authenticates the hub for THIS site.
	svc, err := fedauth.ParseServiceToken(f.ServiceToken, hubPub)
	if err != nil || svc.SiteID != hub.SiteID.String() {
		fail(401, "bad service token")
		return
	}
	// Read exactly the request body the hub declared, then verify the acting-user
	// assertion is bound to this request (method+path+body) and isn't replayed.
	reqBody := make([]byte, f.BodyLen)
	if f.BodyLen > 0 {
		if _, err := io.ReadFull(body, reqBody); err != nil {
			fail(400, "short body")
			return
		}
	}
	assertion, err := fedauth.ParseAssertion(f.ActorAssertion, hubPub)
	if err != nil || assertion.SiteID != hub.SiteID.String() {
		fail(401, "bad actor assertion")
		return
	}
	if assertion.RequestDigest != fedauth.RequestDigest(f.Method, f.Path, reqBody) {
		fail(401, "assertion does not match request")
		return
	}
	fresh, err := s.deps.Store.UseNonce(ctx, assertion.Nonce, time.Now().Add(2*time.Minute))
	if err != nil || !fresh {
		fail(401, "assertion replay")
		return
	}

	// Synthesize the acting principal from the hub-authorized snapshot.
	hubUserID, _ := uuid.Parse(assertion.HubUserID)
	shadowID, err := s.deps.Store.UpsertShadowUser(ctx, hubUserID, assertion.HubUsername)
	if err != nil {
		fail(500, "shadow user")
		return
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
	principal := &auth.Principal{
		UserID: shadowID, SessionID: uuid.Nil,
		Username: "hub:" + assertion.HubUsername, IsSuperAdmin: super, Permissions: perms,
	}

	// Serve the request through the site's own router with the injected principal.
	target := f.Path
	if f.Query != "" {
		target += "?" + f.Query
	}
	req := httptest.NewRequest(f.Method, target, bytes.NewReader(reqBody))
	if ct := f.Header["Content-Type"]; ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req = req.WithContext(auth.WithFederatedPrincipal(ctx, principal))
	rec := httptest.NewRecorder()
	s.siteHandler.ServeHTTP(rec, req)

	_ = WriteRespHeader(stream, &RespHeader{
		Status: rec.Code,
		Header: map[string]string{"Content-Type": rec.Header().Get("Content-Type")},
	})
	_, _ = stream.Write(rec.Body.Bytes())
}
