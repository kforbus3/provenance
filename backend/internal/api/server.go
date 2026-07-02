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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/fleet-terminal/backend/internal/admin"
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
	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/enrollment"
	"github.com/fleet-terminal/backend/internal/hosts"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/identity"
	"github.com/fleet-terminal/backend/internal/jobs"
	"github.com/fleet-terminal/backend/internal/krl"
	"github.com/fleet-terminal/backend/internal/livesessions"
	"github.com/fleet-terminal/backend/internal/metrics"
	"github.com/fleet-terminal/backend/internal/monitor"
	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/playbook"
	"github.com/fleet-terminal/backend/internal/ratelimit"
	"github.com/fleet-terminal/backend/internal/scan"
	"github.com/fleet-terminal/backend/internal/scheduler"
	"github.com/fleet-terminal/backend/internal/sessionsapi"
	fleetsftp "github.com/fleet-terminal/backend/internal/sftp"
	"github.com/fleet-terminal/backend/internal/sshgw"
	"github.com/fleet-terminal/backend/internal/store"
	"github.com/fleet-terminal/backend/internal/support"
	"github.com/fleet-terminal/backend/internal/system"
	"github.com/fleet-terminal/backend/internal/terminal"
	"github.com/fleet-terminal/backend/internal/ws"
)

// Server holds shared dependencies for HTTP handlers. Module handlers are
// attached in registerRoutes; each milestone extends that surface.
type Server struct {
	Cfg     *config.Config
	DB      *pgxpool.Pool
	Log     *slog.Logger
	Version string

	Store   *store.Store
	Auth    *auth.Service
	CA      *ca.CA
	Issuer  *identity.Issuer
	Gateway *sshgw.Gateway
	Hub     *ws.Hub
	Jobs    *jobs.Registry
	Live    *livesessions.Registry
	Notify  *notify.Service

	scanSvc     *scan.Service
	playbookSvc *playbook.Service
	scheduler   *scheduler.Engine
	backups     *backup.Service
	auditFwd    *auditfwd.Forwarder

	// lastCANotify throttles the CA-rotation reminder (touched only by renewalLoop).
	lastCANotify time.Time

	router chi.Router
}

// NewServer constructs a Server and builds its router.
func NewServer(cfg *config.Config, db *pgxpool.Pool, log *slog.Logger, version string) *Server {
	st := store.New(db)
	authSvc := auth.NewService(st, cfg, log)
	caMgr := ca.New(st, cfg)
	vault := identity.NewVault()
	issuer := identity.NewIssuer(st, caMgr, cfg, log, vault)
	gateway := sshgw.New(cfg, log, vault, issuer)

	s := &Server{
		Cfg: cfg, DB: db, Log: log, Version: version,
		Store:   st,
		Auth:    authSvc,
		CA:      caMgr,
		Issuer:  issuer,
		Gateway: gateway,
		Hub:     ws.NewHub(),
		Jobs:    jobs.NewRegistry(),
		Live:    livesessions.New(),
		Notify:  notify.New(st, cfg, log),
	}

	// Scan + playbook services are shared between their HTTP handlers and the
	// scheduler, so construct them once here.
	s.scanSvc = scan.New(st, cfg, log, gateway, issuer, s.Notify)
	s.playbookSvc = playbook.New(st, cfg, log, issuer, s.Notify)
	s.scheduler = scheduler.New(st, s.scanSvc, s.playbookSvc, log)
	s.backups = backup.New(st, cfg, log)
	s.auditFwd = auditfwd.New(st, log)
	st.SetAuditSink(s.auditFwd.Forward) // forward audit events to syslog/SIEM when enabled

	// On login, mint an ephemeral SSH identity bound to the session; on logout,
	// zeroize the key and revoke its certificates.
	authSvc.SetSessionHooks(
		func(ctx context.Context, userID, sessionID uuid.UUID, username string) {
			principals := dedupe([]string{"fleet", username})
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
		},
	)
	// Re-issue an ephemeral identity for a valid session if the in-RAM vault was
	// cleared (e.g. by a backend restart), so SSH/SFTP survive restarts.
	authSvc.SetEnsureCredential(func(ctx context.Context, userID, sessionID uuid.UUID, username string) {
		if _, ok := vault.Get(sessionID); ok {
			return
		}
		if _, err := issuer.Issue(ctx, sessionID, userID, username, dedupe([]string{"fleet", username})); err != nil {
			log.Warn("re-issue ephemeral identity", "err", err)
		}
	})

	s.router = s.buildRouter()
	return s
}

// InitBackground initializes the CA and starts background schedulers. Call once
// after construction, before serving.
func (s *Server) InitBackground(ctx context.Context) error {
	if err := s.CA.EnsureUserCA(ctx); err != nil {
		return err
	}
	// Reconcile: no SSH session or in-memory worker survives a restart; close any
	// stale "active"/"running" rows so they don't appear stuck forever.
	if n, err := s.Store.CloseStaleSessions(ctx); err == nil && n > 0 {
		s.Log.Info("closed stale ssh sessions on startup", "count", n)
	}
	if n, err := s.Store.FailStaleScans(ctx); err == nil && n > 0 {
		s.Log.Info("failed stale scans on startup", "count", n)
	}
	if n, err := s.Store.FailStaleRemediations(ctx); err == nil && n > 0 {
		s.Log.Info("failed stale remediations on startup", "count", n)
	}
	if n, err := s.Store.FailStalePlaybookRuns(ctx); err == nil && n > 0 {
		s.Log.Info("failed stale playbook runs on startup", "count", n)
	}
	go s.renewalLoop(ctx)
	go s.reaperLoop(ctx)
	go s.retentionLoop(ctx)
	go s.krlLoop(ctx)
	go s.scheduler.Run(ctx)
	go s.backups.Run(ctx)
	go monitor.New(s.Store, s.Cfg, s.Log, s.Gateway, s.Issuer, s.Hub, s.Jobs, s.Notify).Run(ctx)
	return nil
}

// krlLoop rebuilds the certificate revocation list and pushes it to enrolled
// hosts whenever the set of revoked serials changes, so revocations take effect
// on hosts (which enforce it via the RevokedKeys directive installed at enroll).
func (s *Server) krlLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	var lastHash string
	tick := func() {
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
		if hash == lastHash { // no change since last successful push
			s.Jobs.Record("krl-distribution", nil)
			return
		}
		if _, err := s.distributeKRL(ctx); err != nil {
			s.Jobs.Record("krl-distribution", err)
			return
		}
		lastHash = hash
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
	signer, err := s.Issuer.SystemSigner(ctx, []string{"fleet"}, 24*time.Hour)
	if err != nil {
		return 0, err
	}
	hosts, _ := s.Store.ListHosts(ctx, 1000, 0)
	b64 := base64.StdEncoding.EncodeToString(krlBytes)
	cmd := "echo " + b64 + " | base64 -d | sudo tee /etc/ssh/fleet_krl >/dev/null && sudo chmod 644 /etc/ssh/fleet_krl && echo OK"
	pushed := 0
	for i := range hosts {
		h := hosts[i]
		if !h.Enrolled {
			continue
		}
		for _, addr := range dedupe([]string{h.WGAddress, h.Address, h.Hostname}) {
			conn, derr := s.Gateway.DialWithSigner(ctx, signer, addr, h.SSHPort, h.SSHUser)
			if derr != nil {
				continue
			}
			if sess, e := conn.Client.NewSession(); e == nil {
				_, _ = sess.CombinedOutput(cmd)
				sess.Close()
				pushed++
			}
			conn.Close()
			break
		}
	}
	s.Log.Info("distributed KRL", "hosts", pushed, "revokedSerials", len(serials))
	return pushed, nil
}

// retentionLoop prunes session recordings older than the configured retention
// (settings key "recordings".retentionDays; 0 = keep forever), reclaiming disk.
func (s *Server) retentionLoop(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	prune := func() {
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
		s.Jobs.Record("recording-retention", nil)
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
			approvals.Reaper(ctx, deps)
			s.Jobs.Record("approval-expiry", nil)
			s.Auth.ReapStaleSessions(ctx)
			s.Jobs.Record("session-reaper", nil)
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
			s.Issuer.RenewExpiring(ctx)
			s.Jobs.Record("certificate-renewal", nil)
			s.checkCAAge(ctx)
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
		s.registerRoutes(api)
	})

	return r
}

// registerRoutes is the single extension point where module handlers attach.
// Each milestone mounts its module here.
func (s *Server) registerRoutes(r chi.Router) {
	r.Get("/ping", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"pong": "ok"})
	})

	deps := &app.Deps{Store: s.Store, Cfg: s.Cfg, Log: s.Log, Auth: s.Auth, CA: s.Issuer, Gateway: s.Gateway, Live: s.Live, Events: s.Hub, Notify: s.Notify}
	deps.DistributeKRL = s.distributeKRL

	// M2 — first-run wizard + authentication.
	bootstrap.NewHandler(s.Store, s.Cfg).Mount(r)
	auth.NewHandler(s.Auth).Mount(r)

	// M3 — host inventory.
	hosts.Mount(r, deps)

	// M4 — certificate authority & lifecycle.
	certificates.Mount(r, deps, s.CA)

	// M5 — SSH gateway browser terminal.
	terminal.Mount(r, deps, s.Gateway)

	// M8 — host enrollment (WireGuard provisioning + trust).
	enrollment.Mount(r, deps, enrollment.New(s.Store, s.Cfg, s.Log, s.Gateway))

	// M7 — live status WebSocket.
	ws.Mount(r, deps, s.Hub)

	// M9 — audited SFTP file transfer.
	fleetsftp.Mount(r, deps, s.Gateway)

	// OpenSCAP security/compliance scans (over the gateway, privileged signer).
	scan.Mount(r, deps, s.scanSvc)

	// Host support bundles (diagnostics + logs, streamed as a .tar.gz).
	support.Mount(r, deps, support.New(s.Cfg, s.Log, s.Gateway, s.Issuer))

	// AI assistant (read-only NL queries over fleet data via local Ollama).
	assistant.Mount(r, deps, assistant.New(s.Store, s.Log))

	playbook.Mount(r, deps, s.playbookSvc)

	notify.Mount(r, s.Auth, s.Notify)

	// Recurring scans / playbook runs.
	scheduler.Mount(r, deps, s.scheduler)

	// Encrypted database backups (scheduled + on-demand).
	backup.Mount(r, deps, s.backups)

	// Orchestrated modules (admin, audit, sessions, approvals).
	admin.Mount(r, deps)
	auditapi.Mount(r, deps)
	sessionsapi.Mount(r, deps)
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
