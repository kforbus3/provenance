// Package api wires the HTTP router, middleware, and module handlers.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/fleet-terminal/backend/internal/accesspolicy"
	"github.com/fleet-terminal/backend/internal/accesspolicyapi"
	"github.com/fleet-terminal/backend/internal/accessreview"
	"github.com/fleet-terminal/backend/internal/admin"
	"github.com/fleet-terminal/backend/internal/aiaction"
	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/approvals"
	"github.com/fleet-terminal/backend/internal/assistant"
	"github.com/fleet-terminal/backend/internal/auditapi"
	"github.com/fleet-terminal/backend/internal/auditfwd"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/backup"
	"github.com/fleet-terminal/backend/internal/bootstrap"
	"github.com/fleet-terminal/backend/internal/ca"
	"github.com/fleet-terminal/backend/internal/certificates"
	"github.com/fleet-terminal/backend/internal/cluster"
	"github.com/fleet-terminal/backend/internal/cmdindex"
	"github.com/fleet-terminal/backend/internal/command"
	"github.com/fleet-terminal/backend/internal/commandpolicyapi"
	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/dbbroker"
	"github.com/fleet-terminal/backend/internal/digest"
	"github.com/fleet-terminal/backend/internal/dr"
	"github.com/fleet-terminal/backend/internal/enrollment"
	"github.com/fleet-terminal/backend/internal/federation"
	"github.com/fleet-terminal/backend/internal/hosts"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/identity"
	"github.com/fleet-terminal/backend/internal/insights"
	"github.com/fleet-terminal/backend/internal/itsmapi"
	"github.com/fleet-terminal/backend/internal/jobs"
	"github.com/fleet-terminal/backend/internal/k8sbroker"
	"github.com/fleet-terminal/backend/internal/kmsapi"
	"github.com/fleet-terminal/backend/internal/krl"
	"github.com/fleet-terminal/backend/internal/lifecycle"
	"github.com/fleet-terminal/backend/internal/livesessions"
	"github.com/fleet-terminal/backend/internal/metrics"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/monitor"
	"github.com/fleet-terminal/backend/internal/msrc"
	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/overlay"
	"github.com/fleet-terminal/backend/internal/overlaypki"
	"github.com/fleet-terminal/backend/internal/playbook"
	"github.com/fleet-terminal/backend/internal/prefs"
	princ "github.com/fleet-terminal/backend/internal/principals"
	"github.com/fleet-terminal/backend/internal/ratelimit"
	"github.com/fleet-terminal/backend/internal/rdp"
	"github.com/fleet-terminal/backend/internal/reports"
	"github.com/fleet-terminal/backend/internal/reportsched"
	"github.com/fleet-terminal/backend/internal/scan"
	"github.com/fleet-terminal/backend/internal/scheduler"
	"github.com/fleet-terminal/backend/internal/scim"
	"github.com/fleet-terminal/backend/internal/serviceaccounts"
	"github.com/fleet-terminal/backend/internal/sessionsapi"
	fleetsftp "github.com/fleet-terminal/backend/internal/sftp"
	"github.com/fleet-terminal/backend/internal/shadow"
	"github.com/fleet-terminal/backend/internal/sshgw"
	"github.com/fleet-terminal/backend/internal/store"
	"github.com/fleet-terminal/backend/internal/support"
	"github.com/fleet-terminal/backend/internal/system"
	"github.com/fleet-terminal/backend/internal/tenantapi"
	"github.com/fleet-terminal/backend/internal/terminal"
	"github.com/fleet-terminal/backend/internal/uebaapi"
	credvault "github.com/fleet-terminal/backend/internal/vault"
	"github.com/fleet-terminal/backend/internal/vulnscan"
	"github.com/fleet-terminal/backend/internal/winscript"
	"github.com/fleet-terminal/backend/internal/ws"
)

// Server holds shared dependencies for HTTP handlers. Module handlers are
// attached in registerRoutes; each milestone extends that surface.
type Server struct {
	Cfg     *config.Config
	DB      *pgxpool.Pool
	Log     *slog.Logger
	Version string
	// Standby is set when the database is a read-only replica: the router serves
	// only the DR standby console and no background writers run.
	Standby bool

	Store     *store.Store
	Auth      *auth.Service
	CA        *ca.CA
	Issuer    *identity.Issuer
	Gateway   *sshgw.Gateway
	Hub       *ws.Hub
	Jobs      *jobs.Registry
	Live      *livesessions.Registry
	Watch     *livesessions.Broker
	Notify    *notify.Service
	Cluster   *cluster.Coordinator // HA: identity, heartbeat lease, leader election
	backplane *ws.Backplane        // HA: cross-instance event/control bridge

	// overlayPKI is the shared X.509 CA for the certificate-authenticated overlays;
	// overlays maps overlay name -> provisioner ("openvpn"). It is
	// always built, but the CA is created lazily (only when a host uses a cert overlay).
	overlayPKI *overlaypki.PKI
	overlays   map[string]overlay.Overlay

	scanSvc      *scan.Service
	vulnScan     *vulnscan.Service
	msrcSvc      *msrc.Service
	actionReg    *aiaction.Registry
	playbookSvc  *playbook.Service
	winscriptSvc *winscript.Service
	commandSvc   *command.Service
	scheduler    *scheduler.Engine
	backups      *backup.Service
	auditFwd     *auditfwd.Forwarder
	insights     *insights.Service
	digest       *digest.Service
	reportSched  *reportsched.Service
	rotator      *credvault.Rotator

	// deps is the shared module container, built once in NewServer and reused by
	// registerRoutes and the federation service.
	deps *app.Deps
	// federation is nil in standalone mode; non-nil for hub/site.
	federation *federation.Service

	// lastCANotify throttles the CA-rotation reminder (touched only by renewalLoop).
	lastCANotify time.Time

	router chi.Router
}

// NewServer constructs a Server and builds its router. When standby is true the DB
// is a read-only replica: the router exposes only the minimal DR standby console and
// no write subsystem is started (the caller skips InitBackground).
func NewServer(cfg *config.Config, db *pgxpool.Pool, log *slog.Logger, version string, standby bool) *Server {
	st := store.New(db)
	authSvc := auth.NewService(st, cfg, log)
	caMgr := ca.New(st, cfg)
	vault := identity.NewVault()
	issuer := identity.NewIssuer(st, caMgr, cfg, log, vault)
	gateway := sshgw.New(cfg, log, vault, issuer)

	// The certificate-authenticated overlay (OpenVPN) shares the X.509 overlay PKI. It is
	// always constructed so a host can be enrolled onto it per-host, but the overlay CA
	// is created lazily on first use (see InitBackground) — a pure WireGuard deployment
	// never touches it.
	overlayPKI := overlaypki.New(st, cfg)
	overlays := map[string]overlay.Overlay{
		"openvpn": overlay.New(cfg, overlayPKI),
	}

	s := &Server{
		Cfg: cfg, DB: db, Log: log, Version: version, Standby: standby,
		Store:   st,
		Auth:    authSvc,
		CA:      caMgr,
		Issuer:  issuer,
		Gateway: gateway,
		Hub:     ws.NewHub(),
		Jobs:    jobs.NewRegistry(),
		Live:    livesessions.New(),
		Watch:   livesessions.NewBroker(),
		Notify:  notify.New(st, cfg, log),

		overlayPKI: overlayPKI,
		overlays:   overlays,
	}
	hostname, _ := os.Hostname()
	s.Cluster = cluster.New(st, hostname, version, log)
	st.SetInstanceID(s.Cluster.ID()) // tag long-running rows this instance owns

	// Cross-instance event/control bridge (Postgres LISTEN/NOTIFY). Harmless in a
	// single-instance deployment (it only ever skips its own messages).
	s.backplane = ws.NewBackplane(db, s.Cluster.ID().String(), s.Hub, log)
	s.backplane.SetControlHandler(func(action, target string) {
		if action == "terminate" {
			if sid, err := uuid.Parse(target); err == nil {
				if n := s.Live.Close(sid); n > 0 {
					log.Info("closed live connections (remote terminate)", "session", sid, "count", n)
				}
			}
		}
	})
	// Cross-instance live session shadowing: mirror a locally-owned session's frames
	// to peers on demand, and deliver a peer's mirrored frames to local watchers.
	s.Watch.SetPeer(
		func(sid uuid.UUID, f livesessions.Frame) {
			s.backplane.PublishShadowFrame(sid, f.Kind, f.Data, f.Cols, f.Rows)
		},
		func(sid uuid.UUID, want bool) { s.backplane.PublishShadowSub(sid, want) },
	)
	s.backplane.SetShadowHandlers(
		func(action string, sid uuid.UUID, origin string) {
			if action == "shadow_sub" {
				s.Watch.RemoteWatchStart(sid, origin) // no-op unless this instance owns sid
			} else {
				s.Watch.RemoteWatchStop(sid, origin)
			}
		},
		func(sid uuid.UUID, kind string, data []byte, cols, rows int) {
			s.Watch.Publish(sid, livesessions.Frame{Kind: kind, Data: data, Cols: cols, Rows: rows})
		},
	)
	s.Hub.SetBackplane(s.backplane)

	// Scan + playbook services are shared between their HTTP handlers and the
	// scheduler, so construct them once here.
	s.scanSvc = scan.New(st, cfg, log, gateway, issuer, s.Notify)
	s.vulnScan = vulnscan.New(st, cfg, log, gateway, issuer, s.Notify)
	s.msrcSvc = msrc.New(st, cfg.MSRCAPIURL, cfg.MSRCMonths, log)
	// Assistant action registry (propose→confirm→execute, plus approval for guarded
	// actions); wired with the runner hooks it needs so this package reaches into
	// neither the vulnscan nor the auth service directly.
	actionNotify := func(ctx context.Context, a *models.AssistantAction) {
		if s.Notify == nil {
			return
		}
		s.Notify.Notify(ctx, notify.Event{
			Type: notify.EventApprovalPending, Severity: notify.SeverityInfo,
			Title: "Assistant action awaiting approval",
			Body:  a.Preview + " Review it in Approvals.",
		})
	}
	s.actionReg = aiaction.New(st, log, s.vulnScan.Run, authSvc.DestroyUserSessions, actionNotify)
	s.playbookSvc = playbook.New(st, cfg, log, issuer, s.Notify)
	s.winscriptSvc = winscript.New(st, cfg, log, gateway, issuer, s.Notify)
	s.commandSvc = command.New(st, cfg, log, gateway, issuer, s.Notify)
	s.scheduler = scheduler.New(st, s.scanSvc, s.vulnScan, s.msrcSvc, s.playbookSvc, s.winscriptSvc, log)
	s.backups = backup.New(st, cfg, log)
	s.auditFwd = auditfwd.New(st, log)
	s.insights = insights.New(st, log, cfg.MetricHistoryRetention)
	s.digest = digest.New(st, s.insights, s.Notify, log)
	s.reportSched = reportsched.New(st, s.Notify, log)
	s.rotator = credvault.NewRotator(st, gateway, cfg, log, s.Notify)
	st.SetAuditSink(s.auditFwd.Forward) // forward audit events to syslog/SIEM when enabled

	// On login, mint an ephemeral SSH identity bound to the session; on logout,
	// zeroize the key and revoke its certificates.
	authSvc.SetSessionHooks(
		func(ctx context.Context, userID, sessionID uuid.UUID, username string) {
			principals := dedupe([]string{princ.Global, princ.User(username)})
			if _, err := issuer.Issue(ctx, sessionID, userID, username, principals); err != nil {
				log.Warn("issue ephemeral identity", "err", err)
			}
		},
		func(ctx context.Context, _ uuid.UUID, sessionID uuid.UUID, _ string) {
			issuer.DestroySession(ctx, sessionID)
			// Forcibly close any live connections for this session — terminal
			// PTYs and in-flight SFTP transfers both register here.
			if n := s.Live.Close(sessionID); n > 0 {
				log.Info("closed live connections", "session", sessionID, "count", n)
			}
			// In HA the PTY may live on another instance; ask peers to close it too.
			s.Hub.PublishTerminate(sessionID)
		},
	)
	// Mint a per-instance ephemeral identity for a valid session when this instance's
	// in-RAM vault lacks its key — either after a restart, or (in HA) because the
	// session was established on a different instance and this request landed here.
	//
	// ISSUE-OWN-CERT MODEL (HA-safe): each instance mints and holds its OWN keypair
	// for the session and never revokes another instance's still-valid cert. Multiple
	// concurrently-valid certs per session (one per serving instance) are expected and
	// harmless — each private key lives only in its own instance's RAM. Revocation
	// happens only on session end (which revokes all of the session's certs) or when
	// an instance dies (a leader sweep revokes that dead instance's now-keyless certs).
	// Crucially we do NOT revoke here: doing so would kill a live peer's session.
	authSvc.SetEnsureCredential(func(ctx context.Context, userID, sessionID uuid.UUID, username string) {
		if _, ok := vault.Get(sessionID); ok {
			return
		}
		if _, err := issuer.Issue(ctx, sessionID, userID, username, dedupe([]string{princ.Global, princ.User(username)})); err != nil {
			log.Warn("issue ephemeral identity for session", "err", err)
		}
	})

	// Shared module container, built once and reused by registerRoutes and (in
	// hub/site mode) the federation service. This is the SAME container the route
	// handlers use, so a hub-proxied request runs through identical logic.
	s.deps = &app.Deps{Store: s.Store, Cfg: s.Cfg, Log: s.Log, Auth: s.Auth, CA: s.Issuer,
		Gateway: s.Gateway, Live: s.Live, Watch: s.Watch, Events: s.Hub, Notify: s.Notify,
		AccessPolicy: accesspolicy.NewEnforcer(s.Store, s.Log)}
	s.deps.DistributeKRL = s.distributeKRL

	// Multi-site federation is mode-gated: standalone builds no service and mounts no
	// routes, so its behavior is entirely unchanged.
	if !cfg.IsStandalone() {
		fed, err := federation.New(s.deps)
		if err != nil {
			log.Error("federation initialization failed; federation disabled", "err", err)
		} else {
			fed.SetGateway(s.Gateway)
			s.federation = fed
		}
	}

	s.router = s.buildRouter()
	if s.federation != nil {
		s.federation.SetSiteHandler(s.router)
	}
	return s
}

// InitBackground initializes the CA and starts background schedulers. Call once
// after construction, before serving.
func (s *Server) InitBackground(ctx context.Context) error {
	if err := s.CA.EnsureUserCA(ctx); err != nil {
		return err
	}
	// FIPS boot self-check: the active user CA must be an approved key type. A fresh
	// FIPS deploy generates ECDSA; an existing Ed25519 CA means the FIPS CA migration
	// hasn't run — fail closed with a clear pointer rather than issue non-FIPS certs.
	if s.Cfg.FIPSMode {
		if kt := s.CA.ActiveKeyType(); strings.Contains(kt, "ed25519") {
			return fmt.Errorf("FIPS mode: active user CA is %q (not FIPS-approved); "+
				"run the FIPS CA migration (docs/fips-mode-plan.md M2)", kt)
		}
	}
	// Cert overlays: when the deployment DEFAULT is a cert overlay, pre-warm the X.509
	// overlay CA so the first enrollment has issuing material ready. When the default is
	// WireGuard, the CA is created lazily on the first host that opts into a cert overlay
	// (so a pure-WireGuard deployment never creates it).
	if overlay.IsCertOverlay(s.Cfg.Overlay) {
		if err := s.overlayPKI.EnsureCA(ctx); err != nil {
			return fmt.Errorf("overlay PKI: %w", err)
		}
		s.Log.Info("overlay PKI ready", "overlay", s.Cfg.Overlay, "fingerprint", s.overlayPKI.Fingerprint())
	}
	// Start cluster membership first so leadership is established before the
	// singleton loops below decide whether to run, and so reconciliation can see the
	// live-instance set.
	go s.Cluster.Run(ctx)
	go s.backplane.Run(ctx)

	s.reconcileOrphanedWork(ctx)

	go s.renewalLoop(ctx)
	go s.reaperLoop(ctx)
	go s.retentionLoop(ctx)
	go s.commandIndexLoop(ctx)
	go s.digest.Run(ctx, s.isLeader)
	go s.reportSched.Run(ctx, s.isLeader)
	go s.dynamicGroupLoop(ctx)
	go s.krlLoop(ctx)
	go s.vaultRotationLoop(ctx)
	go s.scheduler.Run(ctx)
	go s.backups.Run(ctx, s.isLeader)
	go monitor.New(s.Store, s.Cfg, s.Log, s.Gateway, s.Issuer, s.Hub, s.Jobs, s.Notify).Run(ctx, s.isLeader)
	// Multi-site federation background loops (site: maintain hub link; hub: prune).
	if s.federation != nil {
		s.federation.Start(ctx)
	}
	return nil
}

// isLeader reports whether this instance should run singleton (cluster-wide) work.
// Nil-safe so unit tests without a coordinator still behave as a single leader.
func (s *Server) isLeader() bool {
	return s.Cluster == nil || s.Cluster.IsLeader()
}

// reconcileOrphanedWork fails long-running rows (sessions, scans, runs) left behind
// by instances that are no longer alive. In a single-instance deployment this is
// every stale row (as before a restart); in HA it deliberately spares work owned by
// still-live peers. See the ownership-scoped store methods (P2).
func (s *Server) reconcileOrphanedWork(ctx context.Context) {
	// Reconcile: no SSH session or in-memory worker survives the death of its owning
	// instance; close any stale "active"/"running" rows owned by dead instances so
	// they don't appear stuck forever (while sparing live peers' work).
	lease := cluster.Lease
	if n, err := s.Store.CloseStaleSessions(ctx, lease); err == nil && n > 0 {
		s.Log.Info("closed orphaned ssh sessions", "count", n)
	}
	if n, err := s.Store.CloseStaleRDPRecordings(ctx, lease); err == nil && n > 0 {
		s.Log.Info("closed orphaned rdp recordings", "count", n)
	}
	if n, err := s.Store.FailStaleScans(ctx, lease); err == nil && n > 0 {
		s.Log.Info("failed orphaned scans", "count", n)
	}
	if n, err := s.Store.FailStaleVulnScans(ctx, lease); err == nil && n > 0 {
		s.Log.Info("failed orphaned vuln scans", "count", n)
	}
	if n, err := s.Store.FailStaleRemediations(ctx, lease); err == nil && n > 0 {
		s.Log.Info("failed orphaned remediations", "count", n)
	}
	if n, err := s.Store.FailStalePlaybookRuns(ctx, lease); err == nil && n > 0 {
		s.Log.Info("failed orphaned playbook runs", "count", n)
	}
	if n, err := s.Store.FailStaleCommandRuns(ctx, lease); err == nil && n > 0 {
		s.Log.Info("reconciled stale command runs", "count", n)
	}
	if n, err := s.Store.FailStaleWinScriptRuns(ctx, lease); err == nil && n > 0 {
		s.Log.Info("failed orphaned script runs", "count", n)
	}
	if n, err := s.Store.FailStaleEnrollmentJobs(ctx, lease); err == nil && n > 0 {
		s.Log.Info("failed orphaned enrollment jobs", "count", n)
	}
	// Revoke certificates issued by instances that have died (keyless now). Leader
	// only, since it mutates the shared KRL and pushes it to hosts.
	if s.isLeader() {
		if n, err := s.Store.RevokeDeadInstanceCertificates(ctx, lease); err == nil && n > 0 {
			s.Log.Info("revoked certificates of dead instances", "count", n)
			if _, derr := s.distributeKRL(ctx); derr != nil {
				s.Log.Warn("distribute KRL after dead-instance revoke", "err", derr)
			}
		}
	}
}

// krlLoop rebuilds the certificate revocation list and pushes it to enrolled
// hosts whenever the set of revoked serials changes, so revocations take effect
// on hosts (which enforce it via the RevokedKeys directive installed at enroll).
func (s *Server) krlLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	var lastHash string
	var sinceFull int
	// Force a full re-push periodically even when the KRL is unchanged, so a host
	// that was offline/unreachable when a revocation was pushed still converges to
	// the current KRL (~hourly at a 10-minute tick). distributeKRL is best-effort
	// per host, so this reconciliation is what makes revocation eventually reliable.
	const reconcileEvery = 6
	tick := func() {
		if !s.isLeader() {
			return // singleton: only the leader pushes the KRL on the periodic loop
		}
		if !krl.Available() {
			return
		}
		caKeys, _ := s.Store.ListActiveCAPublicKeys(ctx, "user")
		serials, _ := s.Store.RevokedSerials(ctx)
		krlBytes, err := krl.Build(caKeys, serials)
		if err != nil {
			s.Jobs.Record("krl-distribution", err)
			return
		}
		hash := fmt.Sprintf("%x", sha256.Sum256(krlBytes))
		sinceFull++
		if hash == lastHash && sinceFull < reconcileEvery {
			s.Jobs.Record("krl-distribution", nil)
			return
		}
		if _, err := s.distributeKRL(ctx); err != nil {
			// Leave lastHash/sinceFull so we retry on the next tick until it lands.
			s.Jobs.Record("krl-distribution", err)
			return
		}
		lastHash = hash
		sinceFull = 0
		s.Jobs.Record("krl-distribution", nil)
	}
	tick()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// distributeKRL builds the current KRL and writes it to every enrolled host.
// Returns the number of hosts updated. Hosts read RevokedKeys per-auth, so no
// sshd reload is needed for updates to take effect.
func (s *Server) distributeKRL(ctx context.Context) (int, error) {
	if !krl.Available() {
		return 0, fmt.Errorf("ssh-keygen not available")
	}
	// Drop KRL entries for certificates that have already expired (keeps it small).
	_, _ = s.Store.PruneExpiredRevocations(ctx, time.Now().Add(-s.Cfg.UserCertTTL))
	caKeys, _ := s.Store.ListActiveCAPublicKeys(ctx, "user")
	serials, _ := s.Store.RevokedSerials(ctx)
	krlBytes, err := krl.Build(caKeys, serials)
	if err != nil {
		return 0, err
	}
	// Reach every enrolled host, not just the first page — a revoked cert must be
	// rejected fleet-wide. Push in parallel with a bounded pool so revocation
	// propagates promptly even on a large fleet without stampeding the jump host.
	hosts, _ := s.Store.AllHosts(ctx)
	b64 := base64.StdEncoding.EncodeToString(krlBytes)
	cmd := "echo " + b64 + " | base64 -d | sudo tee /etc/ssh/fleet_krl >/dev/null && sudo chmod 644 /etc/ssh/fleet_krl && echo OK"
	// Kept small: each push opens a fresh SSH connection to the jump host, so a
	// large fan-out would trip its sshd MaxStartups limit (as the monitor sweep
	// did) and drop pushes. Revocation is infrequent, so modest parallelism is fine.
	const krlConcurrency = 8
	sem := make(chan struct{}, krlConcurrency)
	var wg sync.WaitGroup
	var pushed int64
	for i := range hosts {
		h := hosts[i]
		if !h.Enrolled {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			signer, err := s.Issuer.SystemSigner(ctx, s.Issuer.SystemHostPrincipals(h.ID), 24*time.Hour)
			if err != nil {
				return
			}
			for _, addr := range dedupe([]string{h.WGAddress, h.Address, h.Hostname}) {
				conn, derr := s.Gateway.DialWithSigner(ctx, signer, addr, h.SSHPort, h.SSHUser)
				if derr != nil {
					continue
				}
				if sess, e := conn.Client.NewSession(); e == nil {
					_, _ = sess.CombinedOutput(cmd)
					sess.Close()
					atomic.AddInt64(&pushed, 1)
				}
				conn.Close()
				break
			}
		}()
	}
	wg.Wait()
	s.Log.Info("distributed KRL", "hosts", pushed, "revokedSerials", len(serials))
	return int(pushed), nil
}

// retentionLoop prunes session recordings older than the configured retention
// (settings key "recordings".retentionDays; 0 = keep forever), reclaiming disk.
func (s *Server) retentionLoop(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	prune := func() {
		if !s.isLeader() {
			return // singleton: only the leader prunes shared recordings/metadata
		}
		days := s.Store.RecordingRetentionDays(ctx)
		if days <= 0 {
			s.Jobs.Record("recording-retention", nil)
			return
		}
		paths, bytes, err := s.Store.PruneRecordingsBefore(ctx, time.Now().AddDate(0, 0, -days))
		if err != nil {
			s.Jobs.Record("recording-retention", err)
			return
		}
		for _, p := range paths {
			if !filepath.IsAbs(p) {
				p = filepath.Join(s.Cfg.RecordingDir, p)
			}
			_ = os.Remove(p)
		}
		if len(paths) > 0 {
			s.Log.Info("pruned recordings", "count", len(paths), "bytes", bytes, "retentionDays", days)
		}
		// RDP recordings share the same retention window as SSH recordings.
		if rpaths, rbytes, rerr := s.Store.PruneRDPRecordingsBefore(ctx, time.Now().AddDate(0, 0, -days)); rerr == nil {
			for _, p := range rpaths {
				if !filepath.IsAbs(p) {
					p = filepath.Join(s.Cfg.RecordingDir, p)
				}
				_ = os.Remove(p)
			}
			if len(rpaths) > 0 {
				s.Log.Info("pruned rdp recordings", "count", len(rpaths), "bytes", rbytes, "retentionDays", days)
			}
		} else {
			s.Log.Warn("prune rdp recordings", "err", rerr)
		}
		s.Jobs.Record("recording-retention", nil)

		// Prune host metric history past its retention window (0 = keep forever /
		// disabled — the monitor also stops writing when retention is 0).
		if ret := s.Cfg.MetricHistoryRetention; ret > 0 {
			if n, err := s.Store.PruneMetricHistoryBefore(ctx, time.Now().Add(-ret)); err != nil {
				s.Log.Warn("prune metric history", "err", err)
			} else if n > 0 {
				s.Log.Info("pruned metric history", "rows", n, "retention", ret.String())
			}
		}

		s.pruneActivity(ctx)
		s.pruneAudit(ctx)
	}
	prune() // run once on startup
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			prune()
		}
	}
}

// commandIndexLoop reconstructs and indexes the commands typed in recorded SSH
// sessions so they are searchable ("who ran command X"). It runs shortly after startup
// (which also backfills pre-existing recordings) and periodically thereafter; new
// recordings are picked up within one tick. Leader-gated (single writer).
func (s *Server) commandIndexLoop(ctx context.Context) {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		if s.isLeader() {
			s.indexSessionCommands(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// indexSessionCommands processes a batch of not-yet-indexed recordings: it streams each
// asciicast, reconstructs the typed command lines, and stores them. A recording whose
// file is gone (pruned) is marked indexed with no commands so it isn't retried forever.
func (s *Server) indexSessionCommands(ctx context.Context) {
	recs, err := s.Store.UnindexedRecordings(ctx, 100)
	if err != nil {
		s.Jobs.Record("command-index", err)
		return
	}
	indexed := 0
	for _, rec := range recs {
		p := rec.Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(s.Cfg.RecordingDir, p)
		}
		f, oerr := os.Open(p)
		if oerr != nil {
			_ = s.Store.IndexRecordingCommands(ctx, rec.RecordingID, rec.SSHSessionID, nil)
			continue
		}
		cmds := cmdindex.ExtractCommands(f)
		f.Close()
		in := make([]store.SessionCommandInput, 0, len(cmds))
		for _, c := range cmds {
			in = append(in, store.SessionCommandInput{Text: c.Text, Offset: c.Offset})
		}
		if err := s.Store.IndexRecordingCommands(ctx, rec.RecordingID, rec.SSHSessionID, in); err != nil {
			s.Jobs.Record("command-index", err)
			continue
		}
		indexed++
	}
	if indexed > 0 {
		s.Jobs.Record("command-index", nil)
		s.Log.Info("indexed session commands", "recordings", indexed)
	}
}

// pruneActivity trims operational history (SSH sessions, SFTP transfers, scans +
// their on-disk reports, playbook runs, login attempts) past ActivityRetention.
// 0 = keep forever. Errors are logged, not fatal — a failed prune must never take
// down the server.
func (s *Server) pruneActivity(ctx context.Context) {
	ret := s.Cfg.ActivityRetention
	if ret <= 0 {
		return
	}
	cutoff := time.Now().Add(-ret)

	if paths, err := s.Store.PruneScansBefore(ctx, cutoff); err != nil {
		s.Log.Warn("prune scans", "err", err)
	} else {
		for _, p := range paths {
			if !filepath.IsAbs(p) {
				p = filepath.Join(s.Cfg.ScanDir, p)
			}
			_ = os.Remove(p)
		}
		if len(paths) > 0 {
			s.Log.Info("pruned scan reports", "files", len(paths), "retention", ret.String())
		}
	}

	prune := func(name string, fn func(context.Context, time.Time) (int64, error)) {
		if n, err := fn(ctx, cutoff); err != nil {
			s.Log.Warn("prune "+name, "err", err)
		} else if n > 0 {
			s.Log.Info("pruned "+name, "rows", n, "retention", ret.String())
		}
	}
	// SSH sessions before recordings-dependent rows are gone is handled inside the
	// store method (it skips sessions that still have a recording).
	prune("ssh sessions", s.Store.PruneSSHSessionsBefore)
	prune("sftp transfers", s.Store.PruneSFTPTransfersBefore)
	prune("playbook runs", s.Store.PrunePlaybookRunsBefore)
	prune("auth events", s.Store.PruneAuthEventsBefore)
	// Expired session/host cert metadata and resolved access requests also grow
	// unbounded; prune both (the cert prune is expiry-keyed, the approval prune skips
	// pending requests and any still holding a live grant — see the store methods).
	prune("expired certificates", s.Store.PruneExpiredCertificatesBefore)
	prune("approval requests", s.Store.PruneApprovalRequestsBefore)
	prune("host status events", s.Store.PruneStatusEventsBefore)
	s.Jobs.Record("activity-retention", nil)
}

// pruneAudit trims the audit chain past AuditRetention. Kept separate from
// activity retention and defaulting to keep-forever, because pruning the chain
// shortens the window a genesis-to-now verification can cover.
func (s *Server) pruneAudit(ctx context.Context) {
	ret := s.Cfg.AuditRetention
	if ret <= 0 {
		return
	}
	if n, err := s.Store.PruneAuditEventsBefore(ctx, time.Now().Add(-ret)); err != nil {
		s.Log.Warn("prune audit events", "err", err)
	} else if n > 0 {
		s.Log.Info("pruned audit events", "rows", n, "retention", ret.String())
	}
	s.Jobs.Record("audit-retention", nil)
}

// vaultRotationLoop rotates vaulted password credentials whose scheduled rotation is
// due. Leader-gated (a singleton across the cluster) and RLS-bypassed (ctx is the
// background context) so it sees due credentials across all tenants — each version
// write inherits the credential's own tenant. FLEET_VAULT_ROTATION_CHECK only sets how
// often the leader checks; the per-credential interval is configured per credential.
func (s *Server) vaultRotationLoop(ctx context.Context) {
	interval := s.Cfg.VaultRotationCheck
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	run := func() {
		if !s.isLeader() {
			return // singleton: only the leader rotates
		}
		n, err := s.rotator.RunDue(ctx)
		if n > 0 {
			s.Log.Info("rotated vault credentials on schedule", "count", n)
		}
		s.Jobs.Record("vault-rotation", err)
	}
	run() // an initial pass shortly after boot
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// dynamicGroupLoop periodically recomputes rule-managed (dynamic) group
// membership so host, tag, and inventory changes are reflected without per-change
// hooks. Runs once shortly after startup, then on an interval.
func (s *Server) dynamicGroupLoop(ctx context.Context) {
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			t.Reset(3 * time.Minute)
			if !s.isLeader() {
				continue // singleton work: only the leader reconciles dynamic groups
			}
			if err := s.Store.ReconcileDynamicGroups(ctx); err != nil {
				s.Log.Warn("reconcile dynamic groups", "err", err)
			}
			s.Jobs.Record("dynamic-groups", nil)
		}
	}
}

// reaperLoop periodically expires elapsed just-in-time access grants and ends
// idle/expired sessions (force-closing their live terminal/SFTP connections).
func (s *Server) reaperLoop(ctx context.Context) {
	deps := &app.Deps{Store: s.Store, Cfg: s.Cfg, Log: s.Log, Auth: s.Auth}
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !s.isLeader() {
				continue // singleton work: only the leader expires grants/sessions
			}
			// Reconcile work orphaned by instances that have since died (their lease
			// expired) — the boot pass only catches instances already dead at startup.
			s.reconcileOrphanedWork(ctx)
			s.Jobs.Record("orphan-reconcile", nil)
			approvals.Reaper(ctx, deps)
			s.Jobs.Record("approval-expiry", nil)
			s.Auth.ReapStaleSessions(ctx)
			s.Jobs.Record("session-reaper", nil)
			if _, err := s.actionReg.Expire(ctx); err == nil {
				s.Jobs.Record("assistant-action-expiry", nil)
			}
			if _, err := s.Store.ExpireVaultCheckouts(ctx); err == nil {
				s.Jobs.Record("vault-checkout-expiry", nil)
			}
		}
	}
}

func (s *Server) renewalLoop(ctx context.Context) {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Per-instance: each instance renews the sessions whose keys live in its
			// own RAM vault, so this must run on every instance, not just the leader.
			s.Issuer.RenewExpiring(ctx)
			s.Jobs.Record("certificate-renewal", nil)
			if s.isLeader() {
				s.checkCAAge(ctx) // singleton notification
			}
		}
	}
}

// checkCAAge sends a rotation-reminder notification when the active SSH CA key
// is older than the configured threshold (it never auto-expires). Throttled to
// roughly weekly so it nudges rather than spams.
func (s *Server) checkCAAge(ctx context.Context) {
	if s.Cfg.CARotateAfter <= 0 {
		return
	}
	created, err := s.Store.ActiveCACreatedAt(ctx, "user")
	if err != nil {
		return
	}
	age := time.Since(created)
	if age < s.Cfg.CARotateAfter {
		return
	}
	if time.Since(s.lastCANotify) < 6*24*time.Hour {
		return
	}
	s.lastCANotify = time.Now()
	days := int(age.Hours() / 24)
	s.Notify.Notify(ctx, notify.Event{
		Type: notify.EventCAKeyAging, Severity: notify.SeverityWarning,
		Title: "SSH CA key due for rotation",
		Body: fmt.Sprintf("Fleet's active SSH certificate authority key is %d days old. "+
			"Consider rotating it (fleetctl rotate-ca, or the Certificates page).", days),
		DedupeKey: "ca-user",
	})
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// Handler returns the root HTTP handler, instrumented with OpenTelemetry so each
// request is a span (a no-op when tracing is disabled).
func (s *Server) Handler() http.Handler {
	return otelhttp.NewHandler(s.router, "fleet-api")
}

func (s *Server) buildRouter() chi.Router {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(realIP(s.Cfg.TrustedProxies)) // trusted-proxy-aware; not chi's spoofable RealIP
	r.Use(securityHeaders)
	r.Use(s.recoverer)
	r.Use(s.metricsMW)
	r.Use(middleware.Timeout(60 * time.Second))
	corsOrigins := []string{s.Cfg.PublicURL}
	if s.Cfg.Environment == "development" {
		// Vite dev server / direct backend — only trusted (with credentials) in dev.
		corsOrigins = append(corsOrigins, "http://localhost:5173", "http://localhost:8080")
	}
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   corsOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Operational endpoints (unauthenticated).
	r.Get("/health", s.handleHealth)
	r.Get("/ready", s.handleReady)
	r.Get("/version", s.handleVersion)
	r.Handle("/metrics", promhttp.Handler())

	// Per-IP rate limiting (defends against bots/abuse when internet-exposed).
	// A stricter limit guards the unauthenticated auth/bootstrap endpoints; a
	// looser one covers the rest of the API. health/ready/metrics are exempt so
	// monitoring is never throttled.
	general := ratelimit.New(s.Cfg.RateLimitPerMin, s.Cfg.RateLimitBurst)
	authLimit := ratelimit.New(s.Cfg.AuthRateLimitPerMin, s.Cfg.AuthRateLimitBurst)
	rateLimitMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			lim := general
			if strings.HasPrefix(req.URL.Path, "/api/v1/auth") || strings.HasPrefix(req.URL.Path, "/api/v1/bootstrap") {
				lim = authLimit
			}
			if !lim.Allow(ratelimit.KeyFromRequest(req)) {
				w.Header().Set("Retry-After", "5")
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, req)
		})
	}

	// Versioned API surface. Module routers mount here.
	r.Route("/api/v1", func(api chi.Router) {
		api.Use(rateLimitMW)
		api.Use(bodyLimitMW)
		if s.Standby {
			// Read-only DR standby: only the break-glass console, nothing that writes.
			dr.MountStandby(api, &app.Deps{Store: s.Store, Cfg: s.Cfg, Log: s.Log}, s.Cfg.DRStandbyToken)
		} else {
			s.registerRoutes(api)
		}
	})

	// Multi-site federation (mode-gated; standalone mounts nothing). Mounted on the
	// TOP-LEVEL router: the site-facing join/link endpoints live outside /api/v1,
	// and MountHub/MountSite add their own /api/v1/federation operator group.
	if !s.Standby {
		if s.Cfg.IsHub() {
			federation.MountHub(r, s.deps, s.federation)
		} else if s.Cfg.IsSite() {
			federation.MountSite(r, s.deps, s.federation)
		}
	}

	return r
}

// bodyLimitMW caps request-body size to blunt memory exhaustion from an oversized
// body, exempting the SFTP upload route (a genuine file transfer already bounded
// by its own configurable MaxUploadBytes). WebSocket upgrades carry no request
// body, so the wrap is a no-op for them.
func bodyLimitMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && !strings.Contains(r.URL.Path, "/sftp/upload") {
			r.Body = http.MaxBytesReader(w, r.Body, 8<<20) // 8 MiB is ample for JSON
		}
		next.ServeHTTP(w, r)
	})
}

// registerRoutes is the single extension point where module handlers attach.
// Each milestone mounts its module here.
func (s *Server) registerRoutes(r chi.Router) {
	r.Get("/ping", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"pong": "ok"})
	})

	deps := s.deps

	// M2 — first-run wizard + authentication. Bootstrap creates the first admin before
	// any tenant exists, so it runs with row-level security bypassed (the admin lands in
	// the provider tenant).
	r.Group(func(gr chi.Router) {
		gr.Use(auth.TenantBypass)
		bootstrap.NewHandler(s.Store, s.Cfg).Mount(gr)
	})
	auth.NewHandler(s.Auth).Mount(r)

	// M3 — host inventory.
	hosts.Mount(r, deps)

	// M4 — certificate authority & lifecycle.
	certificates.Mount(r, deps, s.CA)

	// M5 — SSH gateway browser terminal.
	terminal.Mount(r, deps, s.Gateway)

	// M8 — host enrollment (WireGuard provisioning + trust).
	enrollment.Mount(r, deps, enrollment.New(s.Store, s.Cfg, s.Log, s.Gateway, s.overlays))

	// M7 — live status WebSocket.
	ws.Mount(r, deps, s.Hub)

	// M9 — audited SFTP file transfer.
	fleetsftp.Mount(r, deps, s.Gateway)

	// OpenSCAP security/compliance scans (over the gateway, privileged signer).
	scan.Mount(r, deps, s.scanSvc)
	vulnscan.Mount(r, deps, s.vulnScan, s.msrcSvc)

	// Host support bundles (diagnostics + logs, streamed as a .tar.gz).
	support.Mount(r, deps, support.New(s.Cfg, s.Log, s.Gateway, s.Issuer))

	// AI assistant: read-only NL queries over fleet data (local Ollama) plus guarded
	// actions the user must confirm. The confirm/execute surface is mounted separately.
	assistant.Mount(r, deps, assistant.New(s.Store, s.Log, s.insights, s.Cfg.MetricHistoryRetention, s.actionReg))
	aiaction.Mount(r, deps, s.actionReg)

	insights.Mount(r, deps, s.insights)

	digest.Mount(r, s.Auth, s.digest)

	playbook.Mount(r, deps, s.playbookSvc)
	winscript.Mount(r, deps, s.winscriptSvc)
	command.Mount(r, deps, s.commandSvc)

	notify.Mount(r, s.Auth, s.Notify)

	// Recurring scans / playbook runs.
	scheduler.Mount(r, deps, s.scheduler)

	// Encrypted database backups (scheduled + on-demand).
	backup.Mount(r, deps, s.backups)

	// Orchestrated modules (admin, audit, sessions, approvals).
	admin.Mount(r, deps)
	serviceaccounts.Mount(r, deps)
	tenantapi.Mount(r, deps)
	accessreview.Mount(r, deps)
	scim.Mount(r, deps)
	credvault.Mount(r, deps, s.Gateway)
	dbbroker.Mount(r, deps, s.Gateway)
	rdp.Mount(r, deps, s.Gateway)
	rdp.MountAPI(r, deps)
	auditapi.Mount(r, deps)
	reports.Mount(r, deps)
	reportsched.Mount(r, s.Auth, s.reportSched)
	lifecycle.Mount(r, deps)
	commandpolicyapi.Mount(r, deps)
	dr.Mount(r, deps)
	kmsapi.Mount(r, deps)
	prefs.Mount(r, deps)
	accesspolicyapi.Mount(r, deps)
	k8sbroker.Mount(r, deps)
	uebaapi.Mount(r, deps)
	itsmapi.Mount(r, deps)
	dr.MountPublic(r) // unauthenticated GET /dr/mode → {standby:false} so the SPA can detect posture
	sessionsapi.Mount(r, deps)
	shadow.Mount(r, deps)
	approvals.Mount(r, deps)
	system.Mount(r, deps, s.Jobs)

	// Audit forwarding to syslog/SIEM (admin-configurable).
	auditfwd.Mount(r, s.Auth, s.auditFwd)

	// System health (admin): live status of DB, CA, jump host, runner, backups, jobs.
	r.Group(func(pr chi.Router) {
		pr.Use(s.Auth.RequireAuth)
		pr.With(s.Auth.RequirePermission("System.Configure")).Get("/system/health", s.handleSystemHealth)
	})

}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 2*time.Second)
	defer cancel()
	if err := s.DB.Ping(ctx); err != nil {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "db_unavailable"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{
		"version":     s.Version,         // build label (FLEET_VERSION; "dev" if unset)
		"environment": s.Cfg.Environment, // runtime mode (FLEET_ENV: production|development)
		"appName":     s.appName(r),      // customizable brand name (settings.branding)
	})
}

// appName returns the configured application/brand name from the branding
// setting, falling back to the default. Served publicly so the login and
// bootstrap screens (pre-auth) can render it.
func (s *Server) appName(r *http.Request) string {
	const def = "Fleet Terminal"
	raw, err := s.Store.GetSetting(r.Context(), "branding")
	if err != nil {
		return def
	}
	var b struct {
		AppName string `json:"app_name"`
	}
	if err := json.Unmarshal(raw, &b); err != nil || strings.TrimSpace(b.AppName) == "" {
		return def
	}
	return b.AppName
}

// recoverer converts panics into 500s and logs them.
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.Log.Error("panic recovered", "err", rec, "path", r.URL.Path)
				httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// metricsMW records request counts and latency.
func (s *Server) metricsMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}
		metrics.HTTPRequests.WithLabelValues(r.Method, route, strconv.Itoa(ww.Status())).Inc()
		metrics.HTTPDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
	})
}
