package federation

import (
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/federation/fedauth"
)

// handleProxy relays a management HTTP request into a site's own /api/v1 over the
// control channel. The hub authenticates the operator centrally (RequireAuth) and
// forwards the operator's real permission set inside a signed acting-user
// assertion bound to this exact request; the site enforces it via the injected
// principal. This covers the non-streaming (JSON) management surface — scans,
// playbooks, schedules, host CRUD, certificates, etc.
func (s *Service) handleProxy(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad site id")
		return
	}
	sess, ok := s.registry.Get(siteID)
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "site is not currently linked")
		return
	}
	p := auth.MustPrincipal(r)
	if p == nil {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	// Resolve the target path on the site: everything after ".../proxy/".
	sitePath := "/api/v1/" + chi.URLParam(r, "*")
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body")
		return
	}

	now := time.Now()
	nonce, _ := randToken(16)
	assertion, err := fedauth.IssueAssertion(fedauth.AssertionClaims{
		SiteID:        siteID.String(),
		HubUserID:     p.UserID.String(),
		HubUsername:   p.Username,
		Permissions:   permList(p),
		SuperAdmin:    p.IsSuperAdmin,
		ActionRef:     sitePath,
		RequestDigest: fedauth.RequestDigest(r.Method, sitePath, body),
		Nonce:         nonce,
	}, s.hubPriv, 60*time.Second, now)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "assertion error")
		return
	}
	svc, err := fedauth.IssueServiceToken(s.hubKeyID, siteID.String(), s.hubPriv, 60*time.Second, now)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "service token error")
		return
	}

	stream, err := sess.OpenStream()
	if err != nil {
		writeErr(w, http.StatusBadGateway, "could not open site stream")
		return
	}
	defer stream.Close()

	frame := &Frame{
		Kind: "http", Method: r.Method, Path: sitePath, Query: r.URL.RawQuery,
		Header:         map[string]string{"Content-Type": r.Header.Get("Content-Type")},
		BodyLen:        len(body),
		ServiceToken:   svc,
		ActorAssertion: assertion,
	}
	if err := WriteFrame(stream, frame); err != nil {
		writeErr(w, http.StatusBadGateway, "site write failed")
		return
	}
	if len(body) > 0 {
		if _, err := stream.Write(body); err != nil {
			writeErr(w, http.StatusBadGateway, "site body write failed")
			return
		}
	}

	hdr, br, err := ReadRespHeader(stream)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "no response from site")
		return
	}
	for k, v := range hdr.Header {
		w.Header().Set(k, v)
	}
	status := hdr.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = io.Copy(w, br)
}

// handleProxyTerminal proxies a browser terminal WebSocket to a site host over
// the control channel. The hub authenticates the operator (query token), checks
// Host.Connect centrally, opens a "ws" tunnel stream carrying the acting-user
// assertion, and relays browser frames <-> the stream byte-transparently so the
// binary(stdio)/text(control) protocol is preserved end to end.
func (s *Service) handleProxyTerminal(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad site id")
		return
	}
	sess, ok := s.registry.Get(siteID)
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "site is not currently linked")
		return
	}
	p, err := s.deps.Auth.AuthenticateToken(r.Context(), r.URL.Query().Get("token"))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !p.Has("Host.Connect") {
		writeErr(w, http.StatusForbidden, "missing permission: Host.Connect")
		return
	}
	hostID := chi.URLParam(r, "hostId")
	sitePath := "/api/v1/terminal/" + hostID

	now := time.Now()
	nonce, _ := randToken(16)
	assertion, err := fedauth.IssueAssertion(fedauth.AssertionClaims{
		SiteID: siteID.String(), HubUserID: p.UserID.String(), HubUsername: p.Username,
		Permissions: permList(p), SuperAdmin: p.IsSuperAdmin, ActionRef: sitePath,
		RequestDigest: fedauth.RequestDigest(http.MethodGet, sitePath, nil), Nonce: nonce,
	}, s.hubPriv, 60*time.Second, now)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "assertion error")
		return
	}
	svc, err := fedauth.IssueServiceToken(s.hubKeyID, siteID.String(), s.hubPriv, 60*time.Second, now)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "service token error")
		return
	}
	stream, err := sess.OpenStream()
	if err != nil {
		writeErr(w, http.StatusBadGateway, "could not open site stream")
		return
	}
	defer stream.Close()
	if err := WriteFrame(stream, &Frame{
		Kind: "ws", Method: http.MethodGet, Path: sitePath,
		ServiceToken: svc, ActorAssertion: assertion,
	}); err != nil {
		writeErr(w, http.StatusBadGateway, "site write failed")
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	ws.SetReadLimit(maxWSMsg)
	relayBrowserStream(ws, stream)
}

// relayBrowserStream copies terminal frames both ways between a browser WebSocket
// and a tunnel stream until either side closes.
func relayBrowserStream(ws *websocket.Conn, stream io.ReadWriteCloser) {
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }

	go func() { // browser -> site
		defer stop()
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if err := writeWSMessage(stream, mt, data); err != nil {
				return
			}
		}
	}()
	go func() { // site -> browser
		defer stop()
		for {
			mt, data, err := readWSMessage(stream)
			if err != nil {
				return
			}
			if err := ws.WriteMessage(mt, data); err != nil {
				return
			}
		}
	}()
	<-done
}

// permList flattens a principal's permissions to the assertion snapshot.
func permList(p *auth.Principal) []string {
	if p.IsSuperAdmin || p.Permissions["Admin.All"] {
		return []string{"*"}
	}
	out := make([]string, 0, len(p.Permissions))
	for k, v := range p.Permissions {
		if v {
			out = append(out, k)
		}
	}
	return out
}
