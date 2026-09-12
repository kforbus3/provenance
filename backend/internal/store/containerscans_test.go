package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Which images get scanned, and which are left alone.
//
// grype fetches each image from its registry to scan it, so every unnecessary
// scan is bandwidth, disk and Docker Hub rate limit spent for an answer that
// cannot have changed — on a server that ran out of disk the same week this was
// written. And every scan wrongly SKIPPED is a vulnerable image nobody is told
// about, which is the failure that matters.
func TestContainerImageScanSelection(t *testing.T) {
	dsn := os.Getenv("FLEET_STORE_TEST_DB")
	if dsn == "" {
		t.Skip("set FLEET_STORE_TEST_DB to a Postgres DSN with the schema applied")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	s := &Store{pool: pool}

	d := func(n string) string {
		return "sha256:" + n + "000000000000000000000000000000000000000000000000000000000"
	}
	refs := []ImageRef{
		{Digest: d("a"), Image: "nginx@" + d("a")},
		{Digest: d("b"), Image: "redis@" + d("b")},
		{Digest: d("c"), Image: "app@" + d("c")},
		{Digest: d("e"), Image: "old@" + d("e")},
	}
	t.Cleanup(func() {
		for _, r := range refs {
			_, _ = pool.Exec(ctx, `DELETE FROM container_image_scans WHERE digest=$1`, r.Digest)
		}
	})
	for _, r := range refs {
		_, _ = pool.Exec(ctx, `DELETE FROM container_image_scans WHERE digest=$1`, r.Digest)
	}

	// b: scanned against the current database, clean. Must be left alone.
	if err := s.UpsertContainerImageScan(ctx, ContainerImageScan{
		Digest: d("b"), Image: refs[1].Image, DBBuilt: "2026-09-12"}); err != nil {
		t.Fatalf("upsert b: %v", err)
	}
	// c: scanned, but the scan FAILED. A failed scan is not a scan.
	if err := s.UpsertContainerImageScan(ctx, ContainerImageScan{
		Digest: d("c"), Image: refs[2].Image, DBBuilt: "2026-09-12",
		Error: "unauthorized: authentication required"}); err != nil {
		t.Fatalf("upsert c: %v", err)
	}
	// e: scanned against an OLDER database. The image has not changed, but a new
	// database can turn a clean image into a vulnerable one.
	if err := s.UpsertContainerImageScan(ctx, ContainerImageScan{
		Digest: d("e"), Image: refs[3].Image, DBBuilt: "2026-08-01"}); err != nil {
		t.Fatalf("upsert e: %v", err)
	}

	stale, err := s.StaleContainerImages(ctx, refs, "2026-09-12", 7*24*time.Hour)
	if err != nil {
		t.Fatalf("StaleContainerImages: %v", err)
	}
	got := map[string]bool{}
	for _, r := range stale {
		got[r.Digest] = true
	}

	if !got[d("a")] {
		t.Error("an image never scanned was not selected — it would never be scanned at all")
	}
	if got[d("b")] {
		t.Error("an image scanned against the CURRENT database was selected again; " +
			"its contents cannot have changed, so this is a pull for nothing")
	}
	if !got[d("c")] {
		t.Error("an image whose scan FAILED was not retried — a failed scan is not " +
			"a scan, and recording the error exists so it can be tried again")
	}
	if !got[d("e")] {
		t.Error("an image scanned against an OLDER database was not rescanned — a new " +
			"database can turn a clean image into a vulnerable one without the image changing")
	}

	// With no database build string available, age is the backstop rather than
	// scanning everything on every pass.
	stale2, err := s.StaleContainerImages(ctx, refs, "", 7*24*time.Hour)
	if err != nil {
		t.Fatalf("StaleContainerImages (no db): %v", err)
	}
	for _, r := range stale2 {
		if r.Digest == d("b") {
			t.Error("with no database build string, a recently scanned image was " +
				"selected anyway; age is supposed to be the backstop, not a no-op")
		}
	}
}

// Only digest-pinned containers are scannable, and each distinct image once.
func TestDistinctContainerImages(t *testing.T) {
	dsn := os.Getenv("FLEET_STORE_TEST_DB")
	if dsn == "" {
		t.Skip("set FLEET_STORE_TEST_DB to a Postgres DSN with the schema applied")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	s := &Store{pool: pool}

	var h1, h2 uuid.UUID
	mk := func(name string) uuid.UUID {
		var id uuid.UUID
		if err := pool.QueryRow(ctx,
			`INSERT INTO hosts (hostname, address) VALUES ($1,'10.9.8.1') RETURNING id`,
			name).Scan(&id); err != nil {
			t.Fatalf("create host: %v", err)
		}
		return id
	}
	n := uuid.NewString()[:8]
	h1, h2 = mk("ci-"+n+"-1"), mk("ci-"+n+"-2")
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM host_inventory WHERE host_id=ANY($1)`, []uuid.UUID{h1, h2})
		_, _ = pool.Exec(ctx, `DELETE FROM hosts WHERE id=ANY($1)`, []uuid.UUID{h1, h2})
	})

	// Both hosts run the SAME image, plus one each of their own, plus one whose
	// digest never resolved.
	shared := `{"name":"a","repository":"nginx","digest":"sha256:shared"}`
	inv := func(id uuid.UUID, extra string) {
		if _, err := pool.Exec(ctx, `
			INSERT INTO host_inventory (host_id, containers) VALUES ($1, $2::jsonb)
			ON CONFLICT (host_id) DO UPDATE SET containers=EXCLUDED.containers`,
			id, "["+shared+","+extra+"]"); err != nil {
			t.Fatalf("inventory: %v", err)
		}
	}
	inv(h1, `{"name":"b","repository":"redis","digest":"sha256:one"}`)
	inv(h2, `{"name":"c","repository":"app","digest":""}`)

	got, err := s.DistinctContainerImages(ctx)
	if err != nil {
		t.Fatalf("DistinctContainerImages: %v", err)
	}
	seen := map[string]int{}
	for _, r := range got {
		seen[r.Digest]++
	}

	if seen["sha256:shared"] != 1 {
		t.Errorf("the image both hosts run appears %d times; scanning it per host "+
			"multiplies bandwidth and rate-limit pressure for an identical answer",
			seen["sha256:shared"])
	}
	if seen["sha256:one"] != 1 {
		t.Error("an image only one host runs was missed")
	}
	if seen[""] != 0 {
		t.Error("a container with no resolved digest was included; there is no way " +
			"to scan what is actually running, and a tag would scan something else")
	}
	// The reference must be pullable: a bare digest is not.
	for _, r := range got {
		if r.Digest == "sha256:shared" && r.Image != "nginx@sha256:shared" {
			t.Errorf("image ref = %q, want repository@digest", r.Image)
		}
	}
}
