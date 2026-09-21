// Package rdp brokers RDP (Windows desktop) sessions to the browser via a guacd
// sidecar. The browser speaks the Guacamole protocol over a WebSocket; the backend
// authenticates the user, resolves the host's vaulted credential (the operator
// never sees it), tunnels guacd → jump host → target:3389, and proxies the stream.
//
// Sessions are recorded: guacd writes a Guacamole-protocol recording to a shared
// volume, and the backend stores metadata (rdp_recordings) so the session can be
// replayed later via Guacamole.SessionRecording. See handlers_api.go for replay.
package rdp

import (
	"context"
	"fmt"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/wwt/guac"
	"golang.org/x/crypto/ssh"

	"github.com/kforbus3/provenance/backend/internal/accesspolicy"
	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/credinject"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/sshgw"
	"github.com/kforbus3/provenance/backend/internal/store"
)

type handler struct {
	d  *app.Deps
	gw *sshgw.Gateway

	mu     sync.Mutex
	active map[string]*activeSession // keyed by guacd connection id
}

// activeSession is the in-flight state for one live RDP session, finalized when the
// WebSocket disconnects: the recording (if any) is closed out and the per-session
// redirected-drive directory (if any) is removed.
type activeSession struct {
	recID     uuid.UUID // uuid.Nil when the session is not being recorded
	recPath   string
	driveDir  string // per-session redirected-drive dir to clean up, or ""
	start     time.Time
	actorID   uuid.UUID
	actorName string
	tenantID  uuid.UUID // caller's tenant, so the disconnect finalize can scope RLS
	hostID    uuid.UUID
	hostname  string
	rdpUser   string
}

// Mount attaches the RDP WebSocket endpoint. Like the terminal, it authenticates
// via a query-param token (browsers can't set headers on a WebSocket upgrade).
func Mount(r chi.Router, d *app.Deps, gw *sshgw.Gateway) {
	h := &handler{d: d, gw: gw, active: map[string]*activeSession{}}
	ws := guac.NewWebsocketServer(h.connect)
	ws.OnDisconnect = h.onDisconnect
	r.Handle("/rdp/{hostId}", ws)
}

// recordingDir is where guacd writes RDP recordings — a subdir of the shared
// recordings volume. guacd and the backend mount that volume at the same path, so
// this string is valid on both sides.
func (h *handler) recordingDir() string {
	return filepath.Join(h.d.Cfg.RecordingDir, "rdp")
}

// connect wraps the session setup so any failure is logged (the guac WebSocket
// server otherwise swallows the error, surfacing only as an instant "session ended"
// in the browser with nothing in the backend log to explain it).
func (h *handler) connect(r *http.Request) (guac.Tunnel, error) {
	tunnel, err := h.connectSession(r)
	if err != nil {
		h.d.Log.Warn("rdp: session setup failed", "host", chi.URLParam(r, "hostId"), "err", err)
	}
	return tunnel, err
}

// connectSession authenticates the request, resolves the target + credential, sets up
// the tunnel, and returns a Guacamole tunnel to guacd. Any error aborts the upgrade.
func (h *handler) connectSession(r *http.Request) (guac.Tunnel, error) {
	ctx := r.Context()
	p, err := h.d.Auth.AuthenticateToken(ctx, r.URL.Query().Get("token"))
	if err != nil {
		return nil, fmt.Errorf("unauthorized")
	}
	if !p.Has("Host.Connect") {
		return nil, fmt.Errorf("forbidden")
	}
	// Bypasses RequireAuth — scope to the caller's tenant so the host lookup, credential
	// injection, and recording writes aren't RLS-denied under multi-tenancy.
	ctx = h.d.Auth.TenantScope(ctx, p)
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
	// ABAC: contextual policies may deny this connection on top of RBAC.
	if dec := h.d.AccessPolicy.Authorize(ctx, accesspolicy.ConnCtx{
		UserID: p.UserID, Username: p.Username, IsSuper: p.IsSuperAdmin,
		HostID: host.ID, HostName: host.Hostname, Environment: host.Environment,
		Tags: host.Tags, Protocol: host.Protocol, Surface: "rdp", IP: httpx.ClientIP(r),
	}); dec.Denied {
		return nil, fmt.Errorf("%s", dec.Reason)
	}

	key, err := h.d.Cfg.VaultKey()
	if err != nil {
		return nil, err
	}
	username, password, err := credinject.PasswordFor(ctx, h.d.Store, key, h.d.Cfg.ExtSecret(), host, p.UserID)
	if err != nil {
		return nil, err
	}

	// Tunnel to the host's RDP port through the jump host, and expose it to guacd
	// via an ephemeral local listener (guacd reaches this backend, not the target).
	// Only reach for the overlay address once the host is actually
	// enrolled (tunnel up); before that the overlay isn't routing and the direct
	// management address is what works. Try candidates in order so a not-yet-live
	// overlay falls back to the direct address (unless strict overlay mode is on).
	strictWG := h.d.Store.RequireOverlay(ctx)
	cands := rdpCandidates(host, strictWG)
	if len(cands) == 0 {
		return nil, fmt.Errorf("host has no address")
	}
	var rawConn net.Conn
	var jumpClient *ssh.Client
	var connectedAddr string
	for _, addr := range cands {
		rawConn, jumpClient, err = h.gw.DialRawViaJump(ctx, p.SessionID.String(), addr, host.RDPPort)
		if err == nil {
			connectedAddr = addr
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("could not reach the host over RDP: %w", err)
	}
	// Who may claim this tunnel. Resolved BEFORE the listener exists, so a session is
	// never opened that would accept from anyone: if the guacd address cannot be
	// resolved the session fails here rather than proxying to whoever turns up.
	allowedPeers, err := expectedProxyPeers(h.d.Cfg.GuacdAddr)
	if err != nil {
		rawConn.Close()
		_ = jumpClient.Close()
		return nil, fmt.Errorf("could not determine which peer may claim the RDP tunnel: %w", err)
	}
	//nolint:gosec // ephemeral single-use per-session proxy (30s accept deadline, closed after one conn) that the separate guacd container must reach cross-network via RDPProxyHost; the accepted peer is checked against GuacdAddr
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		rawConn.Close()
		_ = jumpClient.Close()
		return nil, fmt.Errorf("could not open tunnel: %w", err)
	}
	proxyPort := ln.Addr().(*net.TCPAddr).Port
	go proxyOnce(ln, rawConn, jumpClient, allowedPeers, h.d.Log)

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
	applyRDPOptions(cfg, host.RDPOptions)

	sess := &activeSession{
		start: time.Now(), actorID: p.UserID, actorName: p.Username, tenantID: p.TenantID,
		hostID: host.ID, hostname: host.Hostname, rdpUser: username,
	}
	// Record the session: guacd streams a Guacamole recording to the shared volume.
	// If we can't register the recording, the session still proceeds unrecorded.
	h.startRecording(ctx, r, p, host, username, cfg, sess)
	// Drive redirection: guacd exposes a per-session directory as a drive in the
	// desktop; the browser transfers files through it. Isolated per session.
	sess.driveDir = setupDrive(h.d.Cfg.RDPDriveDir, host.RDPOptions, cfg)

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

	tunnel := guac.NewSimpleTunnel(stream)
	h.mu.Lock()
	h.active[tunnel.ConnectionID()] = sess
	h.mu.Unlock()

	_, _ = h.d.Store.AppendAudit(ctx, models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: "session.rdp_start",
		TargetKind: "host", TargetID: host.ID.String(),
		Detail: map[string]any{
			"hostname":       host.Hostname,
			"rdpUser":        username,
			"security":       cfg.Parameters["security"],
			"clipboardCopy":  host.RDPOptions.ClipboardCopy,
			"clipboardPaste": host.RDPOptions.ClipboardPaste,
			"driveEnabled":   host.RDPOptions.EnableDrive,
			// Connection provenance: the exact address the session was brokered to,
			// and whether that is the host's WireGuard overlay address. This is the
			// tamper-evident (hash-chained) record that the session rode the overlay.
			"targetAddress": connectedAddr,
			"overlay":       host.WGAddress != "" && connectedAddr == host.WGAddress,
		},
	})
	return tunnel, nil
}

// setupDrive configures guacd's redirected-drive parameters when the host enables
// it, using a fresh per-session subdirectory (so sessions never share files), and
// returns that directory for cleanup on disconnect (or "" if the drive is off).
func setupDrive(baseDir string, o models.RDPOptions, cfg *guac.Config) string {
	if !o.EnableDrive {
		return ""
	}
	dir := filepath.Join(baseDir, uuid.New().String())
	cfg.Parameters["enable-drive"] = "true"
	cfg.Parameters["drive-name"] = "Provenance"
	cfg.Parameters["drive-path"] = dir
	cfg.Parameters["create-drive-path"] = "true"
	// Gate each transfer direction (default off = both disabled).
	cfg.Parameters["disable-upload"] = boolStr(!o.DriveUpload)
	cfg.Parameters["disable-download"] = boolStr(!o.DriveDownload)
	return dir
}

// applyRDPOptions maps a host's RDPOptions onto guacd connection parameters. Unset
// fields are left at guacd's defaults. Clipboard is disabled per direction unless the
// host explicitly opted in (disable-copy / disable-paste are guacd's gates).
func applyRDPOptions(cfg *guac.Config, o models.RDPOptions) {
	switch o.Security {
	case "nla", "tls", "rdp", "vmconnect", "any":
		cfg.Parameters["security"] = o.Security
	}
	if o.ColorDepth == 8 || o.ColorDepth == 16 || o.ColorDepth == 24 || o.ColorDepth == 32 {
		cfg.Parameters["color-depth"] = strconv.Itoa(o.ColorDepth)
	}
	if o.Width > 0 {
		cfg.OptimalScreenWidth = o.Width
	}
	if o.Height > 0 {
		cfg.OptimalScreenHeight = o.Height
	}
	if o.DPI > 0 {
		cfg.OptimalResolution = o.DPI
	}
	if o.DisableAudio {
		cfg.Parameters["disable-audio"] = "true"
	}
	if o.EnableTheming {
		cfg.Parameters["enable-wallpaper"] = "true"
		cfg.Parameters["enable-theming"] = "true"
		cfg.Parameters["enable-font-smoothing"] = "true"
	}
	if o.Domain != "" {
		cfg.Parameters["domain"] = o.Domain
	}
	// Clipboard: gate each direction. Default (no opt-in) disables both.
	cfg.Parameters["disable-copy"] = boolStr(!o.ClipboardCopy)
	cfg.Parameters["disable-paste"] = boolStr(!o.ClipboardPaste)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// startRecording creates the recording row and wires guacd's recording parameters,
// filling the session's recording fields. If the row can't be created, the session
// proceeds unrecorded (recID stays uuid.Nil).
func (h *handler) startRecording(ctx context.Context, r *http.Request, p *auth.Principal, host *models.Host, rdpUser string, cfg *guac.Config, sess *activeSession) {
	id := uuid.New()
	dir := h.recordingDir()
	path := filepath.Join(dir, id.String())
	hostID := host.ID
	_, err := h.d.Store.CreateRDPRecording(ctx, store.RDPRecordingInput{
		ID: id, HostID: &hostID, UserID: &p.UserID, Hostname: host.Hostname,
		ProvUser: p.Username, RDPUser: rdpUser, Path: path, ClientIP: httpx.ClientIP(r),
	})
	if err != nil {
		h.d.Log.Warn("rdp: could not create recording row", "err", err)
		return
	}
	cfg.Parameters["recording-path"] = dir
	cfg.Parameters["recording-name"] = id.String()
	cfg.Parameters["create-recording-path"] = "true"
	sess.recID = id
	sess.recPath = path
}

// onDisconnect finalizes a session when the WebSocket closes: it closes out the
// recording (if any), removes the per-session redirected-drive directory (if any),
// and audits the session end.
func (h *handler) onDisconnect(connID string, _ *http.Request, _ guac.Tunnel) {
	h.mu.Lock()
	sess := h.active[connID]
	delete(h.active, connID)
	h.mu.Unlock()
	if sess == nil {
		return
	}

	// The request context is already cancelled (WS closed); use a fresh one, scoped to
	// the session's tenant so the recording finalize and session.end audit aren't
	// RLS-denied under multi-tenancy.
	ctx, cancel := context.WithTimeout(h.d.Auth.TenantScopeID(context.Background(), sess.tenantID), 15*time.Second)
	defer cancel()

	duration := time.Since(sess.start).Milliseconds()
	if sess.recID != uuid.Nil {
		// guacd (external) wrote the recording as plaintext; now that the session has
		// ended the file is complete, so encrypt it at rest when a key is configured.
		// A failure is logged but never blocks finalize (the plaintext still replays).
		if err := encryptFileAtRest(sess.recPath, h.d.Cfg.RecordingEncryptionKey); err != nil {
			h.d.Log.Warn("rdp: could not encrypt recording at rest", "err", err, "id", sess.recID)
		}
		var size int64
		if fi, err := os.Stat(sess.recPath); err == nil {
			size = fi.Size()
		}
		if err := h.d.Store.FinishRDPRecording(ctx, sess.recID, size, duration); err != nil {
			h.d.Log.Warn("rdp: could not finalize recording", "err", err, "id", sess.recID)
		}
	}
	if sess.driveDir != "" {
		if err := os.RemoveAll(sess.driveDir); err != nil {
			h.d.Log.Warn("rdp: could not remove drive dir", "err", err, "dir", sess.driveDir)
		}
	}
	actorID := sess.actorID
	_, _ = h.d.Store.AppendAudit(ctx, models.AuditEvent{
		ActorID: &actorID, ActorName: sess.actorName, Action: "session.rdp_end",
		TargetKind: "host", TargetID: sess.hostID.String(),
		Detail: map[string]any{"hostname": sess.hostname, "rdpUser": sess.rdpUser, "durationMs": duration},
	})
}

// rdpCandidates returns the addresses to try, in order, when tunnelling to a
// host's RDP port. The overlay address is preferred only once the host
// is enrolled (its tunnel is up); until then, or as a fallback, the direct
// management address / hostname is used. Under strict overlay mode the overlay is
// the only permitted path for an enrolled host.
func rdpCandidates(h *models.Host, strictWG bool) []string {
	var c []string
	if h.Enrolled && h.WGAddress != "" {
		c = append(c, h.WGAddress)
		if strictWG {
			return c
		}
	}
	for _, a := range []string{h.Address, h.Hostname} {
		if a != "" {
			c = append(c, a)
		}
	}
	return dedupe(c)
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func queryInt(r *http.Request, key string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(key)); err == nil && v > 0 {
		return v
	}
	return def
}

// expectedProxyPeers resolves the addresses the guacd sidecar may connect back from.
//
// The ephemeral RDP tunnel has to listen on all interfaces, because guacd runs in a
// separate container and reaches this backend over the shared Docker network (see
// RDPProxyHost). That is what makes the peer check necessary rather than optional:
// whoever connects first gets an authenticated RDP session to a managed host, with
// the brokered credential injected into it.
//
// The answer is not a new secret to distribute. The backend dials guacd itself, at
// this very address, to drive the session — so the only party that should ever call
// back is the host named by GuacdAddr.
func expectedProxyPeers(guacdAddr string) ([]net.IP, error) {
	host, _, err := net.SplitHostPort(guacdAddr)
	if err != nil {
		host = guacdAddr
	}
	if host == "" {
		return nil, fmt.Errorf("no guacd address configured")
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	names, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("resolve guacd host %q: %w", host, err)
	}
	var ips []net.IP
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("guacd host %q resolved to nothing usable", host)
	}
	return ips, nil
}

// peerAllowed reports whether addr is one of the expected guacd addresses.
func peerAllowed(addr net.Addr, allowed []net.IP) bool {
	ta, ok := addr.(*net.TCPAddr)
	if !ok || ta.IP == nil {
		return false
	}
	for _, ip := range allowed {
		if ip.Equal(ta.IP) {
			return true
		}
	}
	return false
}

// proxyOnce accepts guacd's connection on ln and pipes it to the jump-host tunnel,
// tearing everything down when either side closes. If guacd never connects (e.g. the
// handshake failed), the accept deadline prevents a leak.
//
// It accepts from guacd and nobody else. The listener is on an ephemeral port on all
// interfaces, and it used to hand the session to whoever connected first — so any
// other container sharing the network could race guacd for it, and win by simply
// connecting faster. The prize is a live RDP session to a managed host with the
// brokered credential injected: the attacker sees the password and the desktop. For a
// system whose job is to hold credentials so people do not have to, that is the wrong
// way round.
//
// A refused connection does not end the session. The deadline still applies, so a
// losing racer costs the real guacd its remaining seconds and nothing more.
func proxyOnce(ln net.Listener, target net.Conn, jump io.Closer, allowed []net.IP, log *slog.Logger) {
	defer target.Close()
	defer jump.Close()
	deadline := time.Now().Add(30 * time.Second)
	if l, ok := ln.(*net.TCPListener); ok {
		_ = l.SetDeadline(deadline)
	}
	var guacdConn net.Conn
	for {
		c, err := ln.Accept()
		if err != nil {
			_ = ln.Close()
			return
		}
		if peerAllowed(c.RemoteAddr(), allowed) {
			guacdConn = c
			break
		}
		// Loud: on a correctly isolated deployment this never happens, so it means
		// either the network is shared with something it should not be, or somebody
		// is trying to take the session.
		log.Error("rdp tunnel: refused a connection from an unexpected peer",
			"peer", c.RemoteAddr().String(), "expected", ipsString(allowed))
		_ = c.Close()
	}
	_ = ln.Close()
	defer guacdConn.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, guacdConn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(guacdConn, target); done <- struct{}{} }()
	<-done
}

// ipsString renders the expected peers for a log line.
func ipsString(ips []net.IP) string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return strings.Join(out, ",")
}
