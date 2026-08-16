// Command fleetd is the Moorgate API server and SSH gateway.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	// Embed the IANA timezone database in the binary so time.LoadLocation always
	// resolves zones for schedule computation, even without an OS tzdata package.
	_ "time/tzdata"

	"github.com/kforbus3/Moorgate/backend/internal/api"
	"github.com/kforbus3/Moorgate/backend/internal/auth"
	"github.com/kforbus3/Moorgate/backend/internal/config"
	"github.com/kforbus3/Moorgate/backend/internal/cryptoprofile"
	"github.com/kforbus3/Moorgate/backend/internal/db"
	"github.com/kforbus3/Moorgate/backend/internal/secretbox"
	"github.com/kforbus3/Moorgate/backend/internal/telemetry"
	"github.com/kforbus3/Moorgate/backend/internal/tenant"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		// Logger may not exist yet; use stderr as a last resort.
		os.Stderr.WriteString("fatal: " + err.Error() + "\n")
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := telemetry.NewLogger(cfg.LogLevel, cfg.LogFormat)
	log.Info("starting fleetd", "version", version, "env", cfg.Environment)

	// Crypto profile: select the FIPS-approved algorithm set (or default) once, up
	// front. In FIPS mode this FAILS CLOSED if the validated Go crypto module isn't
	// active. The boot-time selectors below must run before any hashing/sealing.
	profile := cryptoprofile.For(cfg.FIPSMode)
	if err := profile.VerifyModuleActive(); err != nil {
		return err
	}
	secretbox.SetFIPS(cfg.FIPSMode)
	auth.SetPasswordFIPS(cfg.FIPSMode)
	auth.SetTOTPAlgorithm(profile.TOTPAlgorithm())
	if cfg.FIPSMode {
		log.Warn("FIPS MODE ENABLED — using FIPS 140-3 approved crypto profile",
			"overlay", cfg.Overlay, "moduleActive", cryptoprofile.ModuleActive())
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Boot, migrations, and every background worker legitimately span all tenants, so
	// the root context bypasses row-level security. HTTP requests get their own context
	// (tenant-scoped by middleware); a request that skips that middleware is denied, not
	// leaked. No effect when FLEET_MULTI_TENANCY is off.
	ctx = tenant.WithBypass(ctx)

	// Unwrap any KMS-protected master passphrases before the CA or credential vault is
	// used. No-op unless an external KMS backend is configured (FLEET_KMS_PROVIDER).
	if cfg.KMSEnabled() {
		kctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := cfg.ResolveSecrets(kctx)
		cancel()
		if err != nil {
			return fmt.Errorf("KMS unseal failed: %w", err)
		}
		log.Info("master passphrases unsealed via external KMS", "provider", cfg.KMSProvider, "keyID", cfg.KMSKeyID)
	}

	shutdownTracing, err := telemetry.SetupTracing(ctx, cfg.TracingOn, cfg.OTLPEndpoint, "fleet-terminal-backend", version, log)
	if err != nil {
		return err
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracing(sctx)
	}()

	pool, err := db.Connect(ctx, cfg.DatabaseURL, cfg.DBMaxConns, cfg.DBMinConns, cfg.MultiTenancy)
	if err != nil {
		return err
	}
	defer pool.Close()
	log.Info("database connected")

	// Read-only DR standby: if the database is a replica (in recovery), this instance
	// cannot write, so it boots into standby mode — no migrations, no background
	// writers, and only a minimal break-glass DR console (see internal/dr). It flips
	// to normal operation on restart once its database has been promoted to primary.
	standby, rerr := db.InRecovery(ctx, pool)
	if rerr != nil {
		return rerr
	}
	if standby {
		log.Warn("database is in recovery — starting in READ-ONLY DR STANDBY mode (no migrations, no background jobs, DR console only)")
	}

	if cfg.MigrateOnStart && !standby {
		applied, merr := db.Migrate(ctx, pool)
		if merr != nil {
			return merr
		}
		if len(applied) > 0 {
			log.Info("migrations applied", "count", len(applied), "versions", applied)
		} else {
			log.Info("migrations up to date")
		}
	}

	srv := api.NewServer(cfg, pool, log, version, standby)
	if !standby {
		if err := srv.InitBackground(ctx); err != nil {
			return err
		}
		log.Info("ssh certificate authority ready")
	}

	httpSrv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Serve on an explicitly-tracked listener so shutdown can AWAIT interactive
	// sessions. Terminal/SFTP/RDP sessions hijack their connection (WebSocket over
	// an upgraded HTTP request); http.Server.Shutdown deliberately does NOT wait for
	// hijacked connections, so without this a SIGTERM would sever live sessions the
	// instant Shutdown returns. drainListener counts every accepted connection and
	// releases it on Close, giving us a WaitGroup to block on while sessions finish.
	ln, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.HTTPAddr, err)
	}
	var (
		connWG  sync.WaitGroup
		nActive int64
	)
	tracked := &drainListener{Listener: ln, wg: &connWG, count: &nActive}

	errCh := make(chan error, 1)
	go func() {
		log.Info("http listening", "addr", cfg.HTTPAddr)
		if e := httpSrv.Serve(tracked); e != nil && !errors.Is(e, http.ErrServerClosed) {
			errCh <- e
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received, draining active sessions", "timeout", cfg.ShutdownTimeout)
	case e := <-errCh:
		return e
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	// Phase 1: stop accepting new connections and let in-flight (non-hijacked) HTTP
	// requests finish. Shutdown closes idle keep-alives and returns once ordinary
	// requests have completed; hijacked interactive sessions are handled in phase 2.
	srvErr := httpSrv.Shutdown(shutdownCtx)

	// A standby never started the cluster coordinator, so there's no leadership to
	// release; the step-down below is only for a normally-running instance.
	if standby {
		awaitConnDrain(shutdownCtx, &connWG, &nActive, log)
		if srvErr != nil {
			return srvErr
		}
		log.Info("standby shutdown complete")
		return nil
	}

	// Step down from cluster leadership BEFORE the deferred pool.Close(): releasing
	// the Postgres advisory lock while the pool is still open lets a standby instance
	// take over on its next tick, instead of the lock lingering until Postgres reaps
	// this (now-dead) connection — which otherwise leaves the fleet unmonitored for
	// minutes after a deploy/restart. Idempotent with the coordinator's own ctx-cancel
	// path. Done before the session drain so a peer resumes singleton work while this
	// instance spends its remaining budget letting operators' live sessions wind down.
	srv.Cluster.Stop()

	// Phase 2: await hijacked WS/SSH/RDP sessions, up to the remaining shutdown budget.
	// New sessions can't start (the listener is closed); this waits for the live ones
	// to end, then exits — severing whatever is still open once the deadline passes.
	awaitConnDrain(shutdownCtx, &connWG, &nActive, log)

	if srvErr != nil {
		log.Error("graceful shutdown failed", "err", srvErr)
		return srvErr
	}
	log.Info("shutdown complete")
	return nil
}

// awaitConnDrain blocks until every tracked connection has closed or ctx expires,
// logging progress. Used to let interactive sessions finish during graceful shutdown.
func awaitConnDrain(ctx context.Context, wg *sync.WaitGroup, count *int64, log *slog.Logger) {
	if atomic.LoadInt64(count) == 0 {
		return
	}
	log.Info("waiting for active sessions to drain", "sessions", atomic.LoadInt64(count))
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			log.Info("all active sessions drained")
			return
		case <-ctx.Done():
			log.Warn("shutdown deadline reached with sessions still active — terminating them",
				"sessions", atomic.LoadInt64(count))
			return
		case <-ticker.C:
			log.Info("draining active sessions", "remaining", atomic.LoadInt64(count))
		}
	}
}

// drainListener wraps a net.Listener so every accepted connection is tracked in a
// WaitGroup. Because interactive sessions hijack their connection (and http.Server
// then stops managing it), this wrapper is the only place shutdown can observe them
// still being open — the WaitGroup empties only when the underlying conn is closed.
type drainListener struct {
	net.Listener
	wg    *sync.WaitGroup
	count *int64
}

func (l *drainListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.wg.Add(1)
	atomic.AddInt64(l.count, 1)
	return &drainConn{Conn: c, wg: l.wg, count: l.count}, nil
}

// drainConn decrements the tracker exactly once, whenever the connection is closed —
// whether by the HTTP server closing an idle keep-alive during Shutdown or by a
// session handler closing its hijacked connection when the session ends.
type drainConn struct {
	net.Conn
	once  sync.Once
	wg    *sync.WaitGroup
	count *int64
}

func (c *drainConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		atomic.AddInt64(c.count, -1)
		c.wg.Done()
	})
	return err
}
