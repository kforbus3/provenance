// Package terminal serves the browser SSH terminal over WebSocket. It relays
// bytes between the WebSocket and an SSH PTY opened by the gateway, records the
// session (asciicast v2), and writes session/audit metadata.
package terminal

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/commandpolicy"
	"github.com/fleet-terminal/backend/internal/credinject"
	"github.com/fleet-terminal/backend/internal/livesessions"
	"github.com/fleet-terminal/backend/internal/metrics"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/recorder"
	"github.com/fleet-terminal/backend/internal/sshgw"
	"github.com/fleet-terminal/backend/internal/store"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// Same-origin is enforced by the reverse proxy / CORS; allow the upgrade here.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Mount attaches the terminal WebSocket endpoint.
func Mount(r chi.Router, d *app.Deps, gw *sshgw.Gateway) {
	h := &handler{d: d, gw: gw}
	// WebSocket auth uses a query-param token (browsers cannot set headers on WS).
	r.Get("/terminal/{hostId}", h.serve)
}

type handler struct {
	d  *app.Deps
	gw *sshgw.Gateway
}

type controlMsg struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
	Data string `json:"data"`
}

func (h *handler) serve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token, wsRespHeader := h.d.Auth.WSToken(r)
	principal, err := h.d.Auth.AuthenticateToken(ctx, token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !principal.Has("Host.Connect") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	hostID, err := uuid.Parse(chi.URLParam(r, "hostId"))
	if err != nil {
		http.Error(w, "bad host id", http.StatusBadRequest)
		return
	}
	// Authorization: group membership or active temporary grant (super admin bypass).
	if !principal.IsSuperAdmin {
		ok, aerr := h.d.Store.UserCanAccessHost(ctx, principal.UserID, hostID)
		if aerr != nil || !ok {
			http.Error(w, "not authorized for host", http.StatusForbidden)
			return
		}
	}
	host, err := h.d.Store.GetHost(ctx, hostID)
	if err != nil {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}

	// The client IP for the audit record: realIP middleware has already resolved
	// r.RemoteAddr to the true client (trusted-proxy aware), so strip the port.
	clientIP := r.RemoteAddr
	if ip, _, splitErr := net.SplitHostPort(clientIP); splitErr == nil {
		clientIP = ip
	}

	conn, err := upgrader.Upgrade(w, r, wsRespHeader)
	if err != nil {
		return
	}
	defer conn.Close()
	// Bound a single inbound frame so a client can't force an unbounded allocation.
	// 1 MiB comfortably covers keystrokes, resize control frames, and large pastes.
	conn.SetReadLimit(1 << 20)

	h.run(ctx, conn, principal, host, clientIP)
}

// run drives a single terminal session lifecycle.
func (h *handler) run(ctx context.Context, ws *websocket.Conn, p *auth.Principal, host *models.Host, clientIP string) {
	// gorilla/websocket permits only one data writer at a time. The output pumps,
	// the setup-error path, and the admin-terminate callback (which fires from an
	// unrelated goroutine) all write frames, so every write goes through this
	// mutex to avoid interleaved frames or a write-side panic. (Close and
	// WriteControl are separately concurrency-safe and don't need it.)
	var writeMu sync.Mutex
	safeWrite := func(mt int, b []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return ws.WriteMessage(mt, b)
	}

	// Register the live connection up front (before the SSH dial) so it can be
	// force-closed the instant the session is revoked — closing the WebSocket
	// unwinds the SSH session and gateway connection via the read/write pumps.
	// There is no race window where a revoke could miss this connection.
	if h.d.Live != nil {
		dereg := h.d.Live.Register(p.SessionID, host.ID, func() {
			_ = safeWrite(websocket.TextMessage, mustJSON(controlMsg{Type: "error", Data: "session terminated by administrator"}))
			_ = ws.Close()
		})
		defer dereg()
	}

	// Candidate addresses the gateway dials through the jump host, in order of
	// preference: the WireGuard overlay address first, then the management
	// address / hostname as a fallback (useful where the overlay data plane is
	// unavailable, e.g. the local userspace-WireGuard test fabric).
	var candidates []string
	for _, a := range []string{host.WGAddress, host.Address, host.Hostname} {
		if a != "" && !contains(candidates, a) {
			candidates = append(candidates, a)
		}
	}
	// Strict overlay mode: when enabled and this host is on the WireGuard overlay,
	// dial ONLY the overlay address. If the tunnel is down the connection is
	// refused rather than silently falling back to the host's direct address.
	strictWG := h.d.Store.RequireWireGuard(ctx)
	if strictWG && host.WGAddress != "" {
		candidates = []string{host.WGAddress}
	}

	sendErr := func(msg string) {
		_ = safeWrite(websocket.TextMessage, mustJSON(controlMsg{Type: "error", Data: msg}))
	}

	// Privilege tier: Host.Sudo (or super admin) lands in the privileged sudo
	// account; everyone else in the host's login-only account.
	loginUser, principals := sshgw.LoginTier(p.IsSuperAdmin || p.Has("Host.Sudo"), host.SSHUser, p.Username)

	// If the host authenticates with a vaulted credential (not Fleet certs), resolve
	// it — the plaintext is used only inside the gateway dial, never exposed here or
	// to the operator.
	var injection *credinject.Injection
	if host.AuthMethod != "" && host.AuthMethod != "fleet_cert" {
		key, kerr := h.d.Cfg.VaultKey()
		if kerr != nil {
			sendErr(kerr.Error())
			return
		}
		var ierr error
		if injection, ierr = credinject.For(ctx, h.d.Store, key, host, p.UserID); ierr != nil {
			sendErr("credential injection failed: " + ierr.Error())
			return
		}
	}

	var gwConn *sshgw.Conn
	var err error
	var connectedAddr string
	for _, addr := range candidates {
		if injection != nil {
			gwConn, err = h.gw.DialAuthViaJump(ctx, p.SessionID.String(), addr, host.SSHPort, injection.LoginUser, injection.Auth)
		} else {
			// Use a certificate unique to this (user, host) pair.
			gwConn, err = h.gw.DialForHost(ctx, p.SessionID, p.UserID, host.ID, p.Username, host.Hostname, addr, host.SSHPort, loginUser, principals)
		}
		if err == nil {
			connectedAddr = addr
			break
		}
	}
	if err != nil || gwConn == nil {
		if err == nil {
			err = fmt.Errorf("no reachable address for host")
		}
		if strictWG && host.WGAddress != "" {
			sendErr("WireGuard is down for this host and strict overlay mode is enabled, so the connection was refused rather than falling back to the direct network. Restore the host's WireGuard tunnel, or disable strict overlay mode in Settings.")
			return
		}
		sendErr("connection failed: " + err.Error())
		return
	}
	defer gwConn.Close()

	session, err := gwConn.Client.NewSession()
	if err != nil {
		sendErr("ssh session failed: " + err.Error())
		return
	}
	defer session.Close()

	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()

	cols, rows := 120, 32
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		sendErr("pty request failed: " + err.Error())
		return
	}
	if err := session.Shell(); err != nil {
		sendErr("shell start failed: " + err.Error())
		return
	}

	// Persist the SSH session record + start recording. Record the certificate
	// serial used, so the session is auditable back to a specific issued cert.
	var certSerial *uint64
	if injection == nil {
		if serial, ok := h.gw.HostCredentialSerial(p.SessionID, host.ID); ok {
			certSerial = &serial
		}
	} else {
		// Record that this session authenticated with an injected vault credential.
		_, _ = h.d.Store.AppendAudit(ctx, models.AuditEvent{
			ActorID: &p.UserID, ActorName: p.Username, Action: "session.credential_injected",
			TargetKind: "host", TargetID: host.ID.String(),
			Detail: map[string]any{"hostname": host.Hostname, "credentialId": injection.SecretID.String()},
		})
	}
	rec, _ := h.d.Store.CreateSSHSession(ctx, store.SSHSessionInput{
		SessionID: &p.SessionID, UserID: &p.UserID, HostID: &host.ID,
		Username: p.Username, Hostname: host.Hostname, CertSerial: certSerial,
		ClientIP: clientIP,
	})
	var sshSessionID uuid.UUID
	if rec != nil {
		sshSessionID = rec.ID
	}
	metrics.ActiveSSHSessions.Inc()
	defer metrics.ActiveSSHSessions.Dec()

	startUnix := time.Now().Unix()
	var capture *recorder.Recorder
	if sshSessionID != uuid.Nil {
		capture, _ = recorder.New(h.d.Cfg.RecordingDir, sshSessionID.String(), cols, rows, startUnix)
	}

	_, _ = h.d.Store.AppendAudit(ctx, models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: "session.start",
		TargetKind: "host", TargetID: host.ID.String(),
		Detail: map[string]any{
			"hostname": host.Hostname, "sshSessionId": sshSessionID,
			// Connection provenance for audit: the exact address the session used and
			// whether it is the host's WireGuard overlay address (tamper-evident proof
			// the session rode the overlay).
			"targetAddress": connectedAddr,
			"overlay":       host.WGAddress != "" && connectedAddr == host.WGAddress,
		},
	})
	// Push a live event so dashboards show who is connected to which host in
	// real time (matched by session.end below).
	if h.d.Events != nil {
		h.d.Events.BroadcastSession("session.start", p.UserID, map[string]any{
			"sshSessionId": sshSessionID, "username": p.Username,
			"hostId": host.ID, "hostname": host.Hostname, "startedAt": startUnix,
		})
	}

	// Command-control policy: load the rules that apply to this host once, and build
	// a guard. With no rules the guard is nil and the input path below is unchanged
	// (byte-for-byte passthrough, zero overhead).
	guard := h.buildCommandGuard(ctx, p, host, sshSessionID, safeWrite)

	var bytesIn, bytesOut int64
	done := make(chan struct{})
	// The stdout pump, stderr pump, and input reader all end by signalling done.
	// A plain check-then-close races (two goroutines EOF at once → double close →
	// panic that the HTTP recoverer can't catch, killing the process), so gate it
	// through a single sync.Once.
	var closeOnce sync.Once
	closeDone := func() { closeOnce.Do(func() { close(done) }) }

	// Keep the connection alive across idle periods and any intermediary reverse
	// proxy: send a periodic ping and require a pong within the read deadline.
	// Browsers answer pings automatically, so an idle terminal (no keystrokes, or a
	// quiet long-running command) no longer trips a proxy's idle timeout — and a
	// genuinely dead peer is detected within ~70s and cleaned up. Without this the
	// terminal relies entirely on the proxy chain never idling out the socket.
	const (
		pongWait   = 70 * time.Second
		pingPeriod = 54 * time.Second
	)
	_ = ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error {
		return ws.SetReadDeadline(time.Now().Add(pongWait))
	})
	go func() {
		t := time.NewTicker(pingPeriod)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				// WriteControl is safe to call concurrently with the output pumps.
				if err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					return
				}
			}
		}
	}()

	// Terminal traffic is genuine session activity, but it flows over this
	// WebSocket rather than the HTTP API — and the idle reaper only tracks
	// last_seen_at, which is bumped by HTTP requests / token refresh. Without
	// touching it here, an actively-used shell whose browser tab is otherwise
	// quiet (backgrounded, no token refresh) looks idle and gets reaped
	// mid-session. Both keystrokes AND command output count, so a long-running
	// command that is printing output keeps the session alive even with no
	// keypresses; only a terminal silent in BOTH directions goes idle (the 12h
	// absolute session cap still bounds an endlessly-chatty process). Throttled
	// to one write per minute. The three callers (stdout pump, stderr pump,
	// input loop) race, so claim each per-minute slot with an atomic CAS and let
	// exactly one goroutine perform the DB write. Baseline at now(): the
	// WS-connect auth already touched.
	const touchInterval = time.Minute
	lastTouchNano := time.Now().UnixNano()
	touchSession := func() {
		if h.d.Store == nil {
			return
		}
		now := time.Now().UnixNano()
		prev := atomic.LoadInt64(&lastTouchNano)
		if now-prev < int64(touchInterval) {
			return
		}
		if !atomic.CompareAndSwapInt64(&lastTouchNano, prev, now) {
			return // another goroutine claimed this window
		}
		_ = h.d.Store.TouchSession(ctx, p.SessionID)
	}

	// SSH stdout/stderr -> WebSocket (and recording).
	pump := func(src interface{ Read([]byte) (int, error) }) {
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				atomic.AddInt64(&bytesOut, int64(n))
				touchSession()
				if capture != nil {
					capture.Output(buf[:n])
				}
				// Fan out to any read-only watchers (four-eyes oversight). Copy the
				// bytes: buf is reused on the next read. Skipped entirely when no one
				// is watching anything (lock-free Active check).
				if h.d.Watch != nil && sshSessionID != uuid.Nil && h.d.Watch.Active() {
					data := make([]byte, n)
					copy(data, buf[:n])
					h.d.Watch.Publish(sshSessionID, livesessions.Frame{Kind: "o", Data: data})
				}
				if werr := safeWrite(websocket.BinaryMessage, buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		closeDone()
	}
	go pump(stdout)
	go pump(stderr)

	// Seed the broker with the starting size so a watcher that joins mid-session
	// renders at the right dimensions before the next resize.
	if h.d.Watch != nil && sshSessionID != uuid.Nil {
		h.d.Watch.Publish(sshSessionID, livesessions.Frame{Kind: "r", Cols: cols, Rows: rows})
	}

	// WebSocket -> SSH stdin / control.
	go func() {
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				break
			}
			switch mt {
			case websocket.BinaryMessage:
				atomic.AddInt64(&bytesIn, int64(len(data)))
				touchSession()
				if capture != nil {
					capture.Input(data)
				}
				fwd, notice := guard.Input(data)
				_, _ = stdin.Write(fwd)
				if notice != "" {
					_ = safeWrite(websocket.BinaryMessage, []byte(notice))
				}
			case websocket.TextMessage:
				var cm controlMsg
				if json.Unmarshal(data, &cm) == nil {
					switch cm.Type {
					case "resize":
						if cm.Cols > 0 && cm.Rows > 0 {
							_ = session.WindowChange(cm.Rows, cm.Cols)
							if capture != nil {
								capture.Resize(cm.Cols, cm.Rows)
							}
							if h.d.Watch != nil && sshSessionID != uuid.Nil {
								h.d.Watch.Publish(sshSessionID, livesessions.Frame{Kind: "r", Cols: cm.Cols, Rows: cm.Rows})
							}
						}
					case "input":
						b := []byte(cm.Data)
						atomic.AddInt64(&bytesIn, int64(len(b)))
						touchSession()
						if capture != nil {
							capture.Input(b)
						}
						fwd, notice := guard.Input(b)
						_, _ = stdin.Write(fwd)
						if notice != "" {
							_ = safeWrite(websocket.BinaryMessage, []byte(notice))
						}
					}
				}
			}
		}
		closeDone()
	}()

	<-done
	_ = session.Close()
	if h.d.Watch != nil && sshSessionID != uuid.Nil {
		h.d.Watch.Publish(sshSessionID, livesessions.Frame{Kind: "end"})
		h.d.Watch.Clear(sshSessionID)
	}

	// Finalize with a FRESH context: the request context (ctx) is cancelled once
	// the WebSocket closes, which would otherwise abort these writes and leave the
	// recording file orphaned without a DB row.
	fin, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	exitCode := 0
	if capture != nil {
		res := capture.Close()
		if _, err := h.d.Store.CreateRecording(fin, recordingInput(sshSessionID, res)); err != nil {
			h.d.Log.Warn("save recording", "session", sshSessionID, "err", err)
		}
	}
	// A pump goroutine may still be draining after done closed; read the counters
	// atomically to match the atomic writes above.
	inTotal, outTotal := atomic.LoadInt64(&bytesIn), atomic.LoadInt64(&bytesOut)
	if sshSessionID != uuid.Nil {
		_ = h.d.Store.EndSSHSession(fin, sshSessionID, exitCode, inTotal, outTotal)
	}
	_, _ = h.d.Store.AppendAudit(fin, models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: "session.end",
		TargetKind: "host", TargetID: host.ID.String(),
		Detail: map[string]any{"bytesIn": inTotal, "bytesOut": outTotal, "sshSessionId": sshSessionID},
	})
	if h.d.Events != nil {
		h.d.Events.BroadcastSession("session.end", p.UserID, map[string]any{
			"sshSessionId": sshSessionID, "username": p.Username,
			"hostId": host.ID, "hostname": host.Hostname,
		})
	}
}

// buildCommandGuard loads the command-control rules that apply to this host and
// returns a guard wired to audit/notify and the approval-waiver store. It returns
// nil when there are no rules, so the input relay is an unchanged passthrough. The
// callbacks fire at most once per entered command (never per keystroke).
func (h *handler) buildCommandGuard(ctx context.Context, p *auth.Principal, host *models.Host, sshSessionID uuid.UUID, safeWrite func(int, []byte) error) *commandpolicy.Guard {
	rules, err := h.d.Store.RulesForHost(ctx, host.ID)
	if err != nil || len(rules) == 0 {
		return nil
	}
	specs := make([]commandpolicy.Spec, 0, len(rules))
	for _, r := range rules {
		specs = append(specs, commandpolicy.Spec{ID: r.ID, Name: r.Name, Action: r.Action, Pattern: r.Pattern})
	}

	// audit records a command-policy decision to the tamper-evident audit log. It
	// uses context.Background so a decision late in a session (whose request ctx may
	// be cancelling) is still recorded.
	audit := func(action, rule, command string) {
		_, _ = h.d.Store.AppendAudit(context.Background(), models.AuditEvent{
			ActorID: &p.UserID, ActorName: p.Username, Action: action,
			TargetKind: "host", TargetID: host.ID.String(),
			Detail: map[string]any{"rule": rule, "command": command, "hostname": host.Hostname, "sshSessionId": sshSessionID},
		})
	}
	notifyEv := func(typ string, sev notify.Severity, title, body string) {
		if h.d.Notify != nil {
			h.d.Notify.Notify(context.Background(), notify.Event{Type: typ, Severity: sev, Title: title, Body: body})
		}
	}

	return commandpolicy.NewGuard(commandpolicy.Compile(specs), commandpolicy.Callbacks{
		HasWaiver: func(ruleID uuid.UUID) bool {
			ok, _ := h.d.Store.ActiveWaiver(context.Background(), p.UserID, host.ID, &ruleID)
			return ok
		},
		OnFlag: func(r commandpolicy.Rule, command string) {
			audit("command.flagged", r.Name, command)
			notifyEv(notify.EventCommandFlagged, notify.SeverityWarning, "Privileged command run",
				p.Username+" ran a flagged command on "+host.Hostname+": "+command)
		},
		OnBlock: func(r commandpolicy.Rule, command string) {
			audit("command.blocked", r.Name, command)
			notifyEv(notify.EventCommandBlocked, notify.SeverityWarning, "Command blocked by policy",
				p.Username+" was blocked on "+host.Hostname+" ("+r.Name+"): "+command)
		},
		OnApprovalRequest: func(r commandpolicy.Rule, command string) {
			ruleID := r.ID
			_, _ = h.d.Store.CreateCommandApproval(context.Background(), &ruleID, p.UserID, p.Username, &host.ID, host.Hostname, command)
			audit("command.approval_requested", r.Name, command)
			notifyEv(notify.EventCommandApproval, notify.SeverityWarning, "Command awaiting approval",
				p.Username+" requested approval to run on "+host.Hostname+" ("+r.Name+"): "+command)
		},
		OnApprovedRun: func(r commandpolicy.Rule, command string) {
			audit("command.approved_run", r.Name, command)
		},
	})
}

func recordingInput(sshSessionID uuid.UUID, res recorder.Result) store.RecordingInput {
	return store.RecordingInput{
		SSHSessionID: sshSessionID, Format: "asciicast-v2", Path: res.Path,
		SizeBytes: res.SizeBytes, DurationMS: res.DurationMS, SHA256: res.SHA256,
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
