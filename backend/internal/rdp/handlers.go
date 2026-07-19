// Package rdp brokers RDP (Windows desktop) sessions to the browser via a guacd
// sidecar. The browser speaks the Guacamole protocol over a WebSocket; the backend
// authenticates the user, resolves the host's vaulted credential (the operator
// never sees it), tunnels guacd → jump host → target:3389, and proxies the stream.
package rdp

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/wwt/guac"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/credinject"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/sshgw"
)

type handler struct {
	d  *app.Deps
	gw *sshgw.Gateway
}

// Mount attaches the RDP WebSocket endpoint. Like the terminal, it authenticates
// via a query-param token (browsers can't set headers on a WebSocket upgrade).
func Mount(r chi.Router, d *app.Deps, gw *sshgw.Gateway) {
	h := &handler{d: d, gw: gw}
	r.Handle("/rdp/{hostId}", guac.NewWebsocketServer(h.connect))
}

// connect authenticates the request, resolves the target + credential, sets up the
// tunnel, and returns a Guacamole tunnel to guacd. Any error aborts the upgrade.
func (h *handler) connect(r *http.Request) (guac.Tunnel, error) {
	ctx := r.Context()
	p, err := h.d.Auth.AuthenticateToken(ctx, r.URL.Query().Get("token"))
	if err != nil {
		return nil, fmt.Errorf("unauthorized")
	}
	if !p.Has("Host.Connect") {
		return nil, fmt.Errorf("forbidden")
	}
	hostID, err := uuid.Parse(chi.URLParam(r, "hostId"))
	if err != nil {
		return nil, fmt.Errorf("invalid host id")
	}
	if !p.IsSuperAdmin {
		ok, aerr := h.d.Store.UserCanAccessHost(ctx, p.UserID, hostID)
		if aerr != nil || !ok {
			return nil, fmt.Errorf("not authorized for host")
		}
	}
	host, err := h.d.Store.GetHost(ctx, hostID)
	if err != nil {
		return nil, fmt.Errorf("host not found")
	}
	if host.Protocol != "rdp" {
		return nil, fmt.Errorf("host is not an RDP host")
	}

	key, err := h.d.Cfg.VaultKey()
	if err != nil {
		return nil, err
	}
	username, password, err := credinject.PasswordFor(ctx, h.d.Store, key, host, p.UserID)
	if err != nil {
		return nil, err
	}

	// Tunnel to the host's RDP port through the jump host, and expose it to guacd
	// via an ephemeral local listener (guacd reaches this backend, not the target).
	addr := firstAddr(host)
	if addr == "" {
		return nil, fmt.Errorf("host has no address")
	}
	rawConn, jumpClient, err := h.gw.DialRawViaJump(ctx, p.SessionID.String(), addr, host.RDPPort)
	if err != nil {
		return nil, fmt.Errorf("could not reach the host over RDP: %w", err)
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		rawConn.Close()
		_ = jumpClient.Close()
		return nil, fmt.Errorf("could not open tunnel: %w", err)
	}
	proxyPort := ln.Addr().(*net.TCPAddr).Port
	go proxyOnce(ln, rawConn, jumpClient)

	// Configure guacd to connect RDP to our ephemeral proxy.
	cfg := guac.NewGuacamoleConfiguration()
	cfg.Protocol = "rdp"
	cfg.Parameters = map[string]string{
		"hostname":      h.d.Cfg.RDPProxyHost,
		"port":          strconv.Itoa(proxyPort),
		"username":      username,
		"password":      password,
		"security":      "any",
		"ignore-cert":   "true",
		"resize-method": "display-update",
	}
	cfg.OptimalScreenWidth = queryInt(r, "width", 1280)
	cfg.OptimalScreenHeight = queryInt(r, "height", 800)

	guacdConn, err := net.DialTimeout("tcp", h.d.Cfg.GuacdAddr, 10*time.Second)
	if err != nil {
		ln.Close()
		rawConn.Close()
		_ = jumpClient.Close()
		return nil, fmt.Errorf("desktop broker (guacd) unavailable: %w", err)
	}
	stream := guac.NewStream(guacdConn, guac.SocketTimeout)
	if err := stream.Handshake(cfg); err != nil {
		guacdConn.Close()
		ln.Close()
		rawConn.Close()
		_ = jumpClient.Close()
		return nil, fmt.Errorf("desktop session setup failed: %w", err)
	}

	_, _ = h.d.Store.AppendAudit(ctx, models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: "session.rdp_start",
		TargetKind: "host", TargetID: host.ID.String(),
		Detail: map[string]any{"hostname": host.Hostname, "rdpUser": username},
	})
	return guac.NewSimpleTunnel(stream), nil
}

func firstAddr(h *models.Host) string {
	for _, a := range []string{h.WGAddress, h.Address, h.Hostname} {
		if a != "" {
			return a
		}
	}
	return ""
}

func queryInt(r *http.Request, key string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(key)); err == nil && v > 0 {
		return v
	}
	return def
}

// proxyOnce accepts a single connection (from guacd) on ln and pipes it to the
// jump-host tunnel, tearing everything down when either side closes. If guacd never
// connects (e.g. handshake failed), the accept deadline prevents a leak.
func proxyOnce(ln net.Listener, target net.Conn, jump io.Closer) {
	defer target.Close()
	defer jump.Close()
	if l, ok := ln.(*net.TCPListener); ok {
		_ = l.SetDeadline(time.Now().Add(30 * time.Second))
	}
	guacdConn, err := ln.Accept()
	_ = ln.Close()
	if err != nil {
		return
	}
	defer guacdConn.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, guacdConn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(guacdConn, target); done <- struct{}{} }()
	<-done
}
