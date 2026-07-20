// Command fleetd is the Fleet Terminal API server and SSH gateway.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	// Embed the IANA timezone database in the binary so time.LoadLocation always
	// resolves zones for schedule computation, even without an OS tzdata package.
	_ "time/tzdata"

	"github.com/fleet-terminal/backend/internal/api"
	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/db"
	"github.com/fleet-terminal/backend/internal/telemetry"
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownTracing, err := telemetry.SetupTracing(ctx, cfg.TracingOn, cfg.OTLPEndpoint, "fleet-terminal-backend", version, log)
	if err != nil {
		return err
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracing(sctx)
	}()

	pool, err := db.Connect(ctx, cfg.DatabaseURL, cfg.DBMaxConns, cfg.DBMinConns)
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

	errCh := make(chan error, 1)
	go func() {
		log.Info("http listening", "addr", cfg.HTTPAddr)
		if e := httpSrv.ListenAndServe(); e != nil && !errors.Is(e, http.ErrServerClosed) {
			errCh <- e
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case e := <-errCh:
		return e
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	srvErr := httpSrv.Shutdown(shutdownCtx)

	// A standby never started the cluster coordinator, so there's no leadership to
	// release; the step-down below is only for a normally-running instance.
	if standby {
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
	// path.
	srv.Cluster.Stop()

	if srvErr != nil {
		log.Error("graceful shutdown failed", "err", srvErr)
		return srvErr
	}
	log.Info("shutdown complete")
	return nil
}
