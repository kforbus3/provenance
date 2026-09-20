package backup

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kforbus3/provenance/backend/internal/config"
	"github.com/kforbus3/provenance/backend/internal/store"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// A pre-upgrade backup must be restorable over the database it was taken from, AFTER
// that database has been migrated by the upgrade it was protecting against.
//
// That is the only situation the pre-upgrade backup exists for, and restoring in place
// could not do it: pg_dump writes DROP for what it contains and nothing for what it
// does not, so on a database that has moved on, those DROPs hit objects later
// migrations made things depend on —
//
//	ERROR: cannot drop constraint vuln_scans_pkey on table public.vuln_scans
//	       because other objects depend on it
//
// — and ON_ERROR_STOP then leaves rows from BOTH sides in the same table.
//
// Gated on a database because the whole point is a real PostgreSQL: the failure is in
// what the server permits, not in anything Go can stand in for.
func TestRestoreOverAMigratedDatabase(t *testing.T) {
	dsn := os.Getenv("PROV_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set PROV_TEST_DATABASE_URL (see `make test-db`)")
	}
	for _, bin := range []string{"pg_dump", "psql", "openssl"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	dir := t.TempDir()
	// A real store: Create reads the retention policy through it, so a nil one is a
	// panic rather than a skipped step.
	svc := New(store.New(pool), &config.Config{
		BackupDir: dir, BackupPassphrase: "restore-test-passphrase", DatabaseURL: dsn,
	}, discardLogger())
	// A row that exists only in the backup, and one that exists only after it.
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS restore_marker (note text)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM restore_marker`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO restore_marker VALUES ('before-backup')`); err != nil {
		t.Fatal(err)
	}

	info, err := svc.Create(ctx)
	if err != nil {
		t.Fatalf("create backup: %v", err)
	}

	// The database moves on: a new table with a dependency, exactly the shape that
	// broke an in-place restore, plus a row that must not survive.
	for _, q := range []string{
		`INSERT INTO restore_marker VALUES ('after-backup')`,
		`CREATE TABLE IF NOT EXISTS restore_newer (id int PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS restore_dependent (id int REFERENCES restore_newer(id))`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("advance schema (%s): %v", q, err)
		}
	}
	pool.Close() // the restore refuses to run while anything else is connected

	res, err := svc.Restore(ctx, info.Name, RestoreOptions{})
	if err != nil {
		t.Fatalf("restore over a migrated database failed: %v", err)
	}
	t.Logf("restored into %s, previous database kept as %s", res.Into, res.Superseded)

	after, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	defer after.Close()

	var notes []string
	rows, err := after.Query(ctx, `SELECT note FROM restore_marker ORDER BY 1`)
	if err != nil {
		t.Fatalf("read markers: %v", err)
	}
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		notes = append(notes, n)
	}
	rows.Close()
	got := strings.Join(notes, ",")
	if got != "before-backup" {
		t.Errorf("after the restore the table holds %q — a restore that leaves rows from "+
			"both sides is the half-applied state this exists to prevent", got)
	}
	// And the schema is the backup's, not a blend of the two.
	var newer bool
	if err := after.QueryRow(ctx,
		`SELECT to_regclass('restore_newer') IS NOT NULL`).Scan(&newer); err != nil {
		t.Fatal(err)
	}
	if newer {
		t.Error("a table created after the backup survived the restore — the restored " +
			"database is a blend of both schemas")
	}
	if res.Superseded == "" {
		t.Error("the previous database was not kept; there is no undo")
	}
}
