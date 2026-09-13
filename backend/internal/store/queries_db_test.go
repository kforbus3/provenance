package store

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kforbus3/provenance/backend/internal/db"
)

// Every read query in this package, executed against a real PostgreSQL.
//
// Nothing here asserts what comes BACK. An empty database returns empty results,
// and that is the point: the failure this exists for is a query that cannot run
// at all.
//
// DiscoveredProjects shipped with a comma where it needed CROSS JOIN LATERAL, so
// a LEFT JOIN could not see the table it joined on. It failed to parse on every
// call, from the release that introduced the screen it feeds — and that screen
// said "no compose projects found yet", which reads as a fact about the fleet.
// The package has no database in its tests and the panel's test mocks the API,
// so a query that could not parse passed the whole gate, twice over.
//
// A compile error in the same file is caught in milliseconds. SQL in a string
// gets no such treatment unless something runs it.
func TestStoreQueriesParse(t *testing.T) {
	url := os.Getenv("PROVENANCE_TEST_DB_URL")
	if url == "" {
		t.Skip("PROVENANCE_TEST_DB_URL is not set; run via `make store-queries`")
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

	id := uuid.New()
	// Each entry runs one query. Add a line here when adding a read method --
	// it costs nothing and is the only thing standing between a malformed query
	// and production.
	cases := []struct {
		name string
		run  func() error
	}{
		{"DiscoveredProjects", func() error { _, err := s.DiscoveredProjects(ctx); return err }},
		{"ImageUpdates", func() error { _, err := s.ImageUpdates(ctx); return err }},
		{"ImageUpdatesWithHosts", func() error { _, err := s.ImageUpdatesWithHosts(ctx, "fleet-terminal"); return err }},
		{"TrackedImages", func() error { _, err := s.TrackedImages(ctx); return err }},
		{"EnabledStackComposes", func() error { _, err := s.EnabledStackComposes(ctx); return err }},
		{"LastCheckedAt", func() error { _, err := s.LastCheckedAt(ctx); return err }},
		{"StaleImageChecks", func() error {
			_, err := s.StaleImageChecks(ctx, []TrackedImage{{Repository: "a/b", Tag: "1"}}, time.Hour)
			return err
		}},
		{"PutCachedTags", func() error { return s.PutCachedTags(ctx, "a/b", []string{"1.0"}, true) }},
		{"CachedTags", func() error { _, _, _ = s.CachedTags(ctx, "a/b", time.Hour); return nil }},
		{"ListStacks", func() error { _, err := s.ListStacks(ctx, nil); return err }},
		{"ListStacksForHost", func() error { _, err := s.ListStacks(ctx, &id); return err }},
		{"ListUpdateRollouts", func() error { _, err := s.ListUpdateRollouts(ctx); return err }},
		{"ActiveUpdateRollouts", func() error { _, err := s.ActiveUpdateRollouts(ctx); return err }},
		{"UpdateRolloutHosts", func() error { _, err := s.UpdateRolloutHosts(ctx, id); return err }},
		{"HostsRunningAnyImage", func() error {
			_, err := s.HostsRunningAnyImage(ctx, []RolloutImage{{Repository: "a/b", FromTag: "1", ToTag: "2"}})
			return err
		}},
		{"HostContainers", func() error { _, err := s.HostContainers(ctx, id); return err }},
		{"DeleteFinishedUpdateRollouts", func() error { _, err := s.DeleteFinishedUpdateRollouts(ctx); return err }},
		{"DeleteUpdateRollout", func() error { return s.DeleteUpdateRollout(ctx, id) }},
		{"MarkStackDeploying", func() error { return s.MarkStackDeploying(ctx, id) }},
		{"PruneImageUpdates", func() error { return s.PruneImageUpdates(ctx, []TrackedImage{{Repository: "a/b", Tag: "1"}}) }},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.run(); malformed(err) {
				t.Errorf("%s: %v", c.name, err)
			}
		})
	}

	// A method added without a line above is a query nothing runs. Named
	// explicitly rather than counted, so the failure says which.
	covered := map[string]bool{}
	for _, c := range cases {
		covered[c.name] = true
	}
	for _, m := range []string{
		"DiscoveredProjects", "ImageUpdates", "ImageUpdatesWithHosts", "TrackedImages",
		"EnabledStackComposes", "LastCheckedAt", "ListStacks", "ListUpdateRollouts",
	} {
		if !covered[m] {
			t.Errorf("%s is not exercised here", m)
		}
		if _, ok := reflect.TypeOf(s).MethodByName(m); !ok {
			t.Errorf("%s no longer exists; update this list", m)
		}
	}
}

// malformed reports whether an error means the QUERY is wrong, as opposed to the
// database simply not holding the row asked for.
//
// An empty database is the point of this test, so "no rows" and a foreign key
// violation are expected and say nothing about the SQL. PostgreSQL class 42 is
// the one that matters: 42601 syntax error, 42703 undefined column, 42P01
// undefined table — which is exactly what DiscoveredProjects returned on every
// call for as long as it existed.
func malformed(err error) bool {
	if err == nil || errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return strings.HasPrefix(pgErr.SQLState(), "42")
	}
	// Not a database error at all — a connection or scan problem, which is worth
	// failing on rather than silently tolerating.
	return true
}
