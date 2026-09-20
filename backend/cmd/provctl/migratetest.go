package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kforbus3/provenance/backend/internal/db"
)

// migrateOnly applies the embedded migrations to a database and stops.
//
// For standing up a throwaway schema to check queries against (see `make test-db` and
// store's TestEverySQLStatementParsesAgainstTheRealSchema). The backend migrates at
// startup, but starting the backend to obtain a schema means bringing up its
// certificate authority, its overlay and its listeners — none of which a query check
// needs, and any of which can fail for reasons that have nothing to do with SQL.
func migrateOnly(ctx context.Context, dsn string) error {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	applied, err := db.Migrate(ctx, pool)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	fmt.Printf("migrations applied: %d\n", len(applied))
	return nil
}
