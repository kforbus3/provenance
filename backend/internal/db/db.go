// Package db owns the PostgreSQL connection pool and schema migrations.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Connect opens a pgx connection pool and verifies connectivity with retries,
// since Postgres may still be starting up in a fresh Compose stack.
func Connect(ctx context.Context, url string, maxConns, minConns int32) (*pgxpool.Pool, error) {
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
