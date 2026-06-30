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

	if cfg.MigrateOnStart {
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

	srv := api.NewServer(cfg, pool, log, version)
	if err := srv.InitBackground(ctx); err != nil {
		return err
	}
	log.Info("ssh certificate authority ready")

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
	if e := httpSrv.Shutdown(shutdownCtx); e != nil {
		log.Error("graceful shutdown failed", "err", e)
		return e
	}
	log.Info("shutdown complete")
	return nil
}
