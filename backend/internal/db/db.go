// Package db owns the PostgreSQL connection pool and schema migrations.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fleet-terminal/backend/internal/tenant"
)

// Connect opens a pgx connection pool and verifies connectivity with retries,
// since Postgres may still be starting up in a fresh Compose stack. When multiTenancy
// is on, a BeforeAcquire hook sets the `app.tenant_id` GUC from the request context on
// every connection, so the row-level-security policies scope every query to the
// caller's tenant (see internal/tenant + migration 0051).
func Connect(ctx context.Context, url string, maxConns, minConns int32, multiTenancy bool) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	if minConns > 0 {
		cfg.MinConns = minConns
	}

	// Scope every acquired connection to the request's tenant so RLS can filter. Set on
	// both modes: with the flag off we set Bypass (RLS is satisfied for all rows, so the
	// FORCE'd policies are a no-op and behavior is unchanged); with it on we set the
	// context's tenant, or "" for an unmarked context — which RLS denies (fail closed).
	cfg.BeforeAcquire = func(ctx context.Context, conn *pgx.Conn) bool {
		val := tenant.Bypass
		if multiTenancy {
			val = tenant.GUCValue(ctx)
		}
		if _, err := conn.Exec(ctx, "SELECT set_config($1, $2, false)", tenant.GUC, val); err != nil {
			return false // don't hand out a connection we couldn't scope
		}
		return true
	}
	cfg.MaxConnLifetime = time.Hour
	cfg.HealthCheckPeriod = 30 * time.Second
	// Recycle idle connections so that after a Postgres failover (pooler/Patroni
	// promoting a new primary) the pool doesn't keep handing out connections pinned
	// to the old, now-unreachable primary. Combined with MaxConnLifetime this bounds
	// how long a stale connection can linger.
	cfg.MaxConnIdleTime = 5 * time.Minute

	// Retry with exponential backoff (capped): tolerates Postgres still starting in a
	// fresh stack, and a brief unavailability window during a primary failover.
	var pool *pgxpool.Pool
	var lastErr error
	backoff := 500 * time.Millisecond
	const maxBackoff = 5 * time.Second
	for attempt := 0; attempt < 30; attempt++ {
		pool, lastErr = pgxpool.NewWithConfig(ctx, cfg)
		if lastErr == nil {
			pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			lastErr = pool.Ping(pingCtx)
			cancel()
			if lastErr == nil {
				// Fail closed on a role that would silently defeat tenant isolation.
				if multiTenancy {
					if err := verifyRLSCapableRole(ctx, pool); err != nil {
						pool.Close()
						return nil, err
					}
				}
				return pool, nil
			}
			pool.Close()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	return nil, fmt.Errorf("database not reachable after retries: %w", lastErr)
}

// verifyRLSCapableRole refuses to start multi-tenant mode on a database role that would
// silently bypass row-level security — a SUPERUSER or a role WITH BYPASSRLS ignores the
// FORCE'd tenant policies, so one tenant could read another tenant's rows (including
// sealed vault secrets) with no error. Fail closed: better to refuse to boot than to run
// with silently-broken isolation.
func verifyRLSCapableRole(ctx context.Context, pool *pgxpool.Pool) error {
	var isSuper, bypassRLS bool
	// current_setting('is_superuser') is 'on'/'off'; rolbypassrls is on the role row.
	err := pool.QueryRow(ctx, `
		SELECT current_setting('is_superuser') = 'on',
		       COALESCE((SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user), false)
	`).Scan(&isSuper, &bypassRLS)
	if err != nil {
		return fmt.Errorf("multi-tenancy: could not verify the database role's RLS enforcement: %w", err)
	}
	if isSuper || bypassRLS {
		why := "is a SUPERUSER"
		if !isSuper {
			why = "has the BYPASSRLS attribute"
		}
		return fmt.Errorf("multi-tenancy is enabled but the database role %s, which BYPASSES row-level security and would break tenant isolation. "+
			"Connect as a non-superuser role created WITH NOBYPASSRLS — e.g. "+
			"`CREATE ROLE fleet_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '…'; GRANT ALL ON ALL TABLES IN SCHEMA public TO fleet_app;` "+
			"— and point FLEET_DATABASE_URL at it", why)
	}
	return nil
}
