package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrateLockKey serializes concurrent migrators via a Postgres advisory lock, so
// that when multiple instances boot together (HA / rolling upgrade) only one applies
// migrations and the others wait, then find everything already applied. Distinct from
// the leader-election lock key.
const migrateLockKey int64 = 0x466C744D696700 // "FltMig"

// Migrate applies all embedded SQL migrations in lexical order exactly once,
// tracking applied versions in schema_migrations. Each file runs in its own
// transaction so a failure rolls back cleanly. Concurrent callers are serialized by a
// session-scoped advisory lock held for the duration.
func Migrate(ctx context.Context, pool *pgxpool.Pool) (applied []string, err error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()
	// Block until we hold the migration lock; a peer migrating concurrently finishes
	// first and we then observe its work as already-applied.
	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrateLockKey); err != nil {
		return nil, fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		// Best-effort unlock on a fresh context (ctx may be done); releasing the conn
		// also frees the session lock.
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrateLockKey)
	}()

	_, err = conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`)
	if err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	for _, name := range files {
		version := strings.TrimSuffix(name, ".sql")
		var exists bool
		if err = conn.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, version,
		).Scan(&exists); err != nil {
			return applied, fmt.Errorf("check migration %s: %w", version, err)
		}
		if exists {
			continue
		}
		body, rerr := migrationsFS.ReadFile("migrations/" + name)
		if rerr != nil {
			return applied, fmt.Errorf("read migration %s: %w", name, rerr)
		}
		tx, berr := conn.Begin(ctx)
		if berr != nil {
			return applied, berr
		}
		if _, eerr := tx.Exec(ctx, string(body)); eerr != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("apply migration %s: %w", name, eerr)
		}
		if _, eerr := tx.Exec(ctx,
			`INSERT INTO schema_migrations(version) VALUES($1)`, version); eerr != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("record migration %s: %w", name, eerr)
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return applied, fmt.Errorf("commit migration %s: %w", name, cerr)
		}
		applied = append(applied, version)
	}
	return applied, nil
}
