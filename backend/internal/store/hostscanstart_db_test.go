package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kforbus3/provenance/backend/internal/db"
)

// Every security scan's started_at equalled its finished_at, so every duration read
// zero and a scan in progress never showed as running: the only write before
// completion happened after oscap had finished. The start must be recorded when the
// scan starts, and survive the later write that records the resolved profile.
func TestAHostScanRecordsWhenItStarted(t *testing.T) {
	url := os.Getenv("PROV_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("no test database offered; run via `make test-db`")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := &Store{pool: pool}
	h, err := s.CreateHost(ctx, HostInput{Hostname: "scanstart-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	sc, err := s.CreateHostScan(ctx, h.ID, nil, "test", "", false)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}

	if err := s.MarkHostScanRunning(ctx, sc.ID); err != nil {
		t.Fatalf("mark running: %v", err)
	}
	var status string
	var started time.Time
	if err := pool.QueryRow(ctx, `SELECT status, started_at FROM host_scans WHERE id=$1`, sc.ID).Scan(&status, &started); err != nil {
		t.Fatal(err)
	}
	if status != "running" {
		t.Fatalf("a started scan must read running, got %q", status)
	}

	// Let time pass, as oscap does, then record the profile the way the scan does
	// once oscap has finished.
	if _, err := pool.Exec(ctx, `SELECT pg_sleep(1.1)`); err != nil {
		t.Fatal(err)
	}
	if err := s.StartHostScan(ctx, sc.ID, "xccdf_p", "Standard", "ds.xml"); err != nil {
		t.Fatalf("record profile: %v", err)
	}
	var after time.Time
	if err := pool.QueryRow(ctx, `SELECT started_at FROM host_scans WHERE id=$1`, sc.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !after.Equal(started) {
		t.Fatalf("recording the profile moved the start from %v to %v -- the zero-duration bug", started, after)
	}

	// Only a pending scan moves: a second start is refused rather than silently
	// matching nothing.
	if err := s.MarkHostScanRunning(ctx, sc.ID); err == nil {
		t.Fatal("marking a scan that is already running must report that it matched nothing")
	}
}
