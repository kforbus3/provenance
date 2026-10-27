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

// The fleet->prov rename moved the hosts.ssh_user column default to 'prov' (migration
// 0097) but CreateHost filled a blank user with "fleet" before the row ever reached
// that default. Every host added with the SSH User field left empty was enrolled
// under the superseded fleet/fleet-login accounts -- devbox on 2026-10-27, the first
// new host after the 09-22 migration had moved every existing one to prov.
func TestANewHostDefaultsToTheProvAccount(t *testing.T) {
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

	blank, err := s.CreateHost(ctx, HostInput{Hostname: "defuser-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	if blank.SSHUser != "prov" {
		t.Fatalf("a host added with no SSH user got %q; enrollment would create that account instead of prov", blank.SSHUser)
	}

	// The Go default and the column default are two statements of one fact; when they
	// disagree, whichever path writes the row decides which account a host gets.
	var colDefault string
	if err := pool.QueryRow(ctx, `SELECT column_default FROM information_schema.columns
		WHERE table_name='hosts' AND column_name='ssh_user'`).Scan(&colDefault); err != nil {
		t.Fatalf("read column default: %v", err)
	}
	if colDefault != "'prov'::text" {
		t.Fatalf("hosts.ssh_user column default is %s, CreateHost defaults to %q", colDefault, blank.SSHUser)
	}

	// An operator who typed a user meant it.
	typed, err := s.CreateHost(ctx, HostInput{Hostname: "defuser-" + uuid.NewString()[:8], SSHUser: "admin"})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	if typed.SSHUser != "admin" {
		t.Fatalf("an explicit SSH user was replaced: got %q, want admin", typed.SSHUser)
	}
}
