package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kforbus3/provenance/backend/internal/db"
)

// Assigning a role by a name that does not name a role must fail.
//
// It returned nil. The query was
//
//	INSERT INTO user_roles (user_id, role_id)
//	SELECT $1, id FROM roles WHERE name=$2 ON CONFLICT DO NOTHING
//
// which inserts nothing and reports no error when the SELECT finds nothing. Every
// caller is an identity provider mapping an IdP group onto a Provenance role, and
// all three discarded the return value on top of that. A Keycloak realm was mapped
// with prov-admins → "Admin" and prov-readonly → "Viewer"; the roles here are
// called Administrator and Read-Only. Both users authenticated perfectly and held
// nothing.
//
// Needs a real database because the whole defect lives in what SQL does with a row
// that is not there.
func TestAssigningARoleThatDoesNotExistFails(t *testing.T) {
	url := os.Getenv("PROV_TEST_DATABASE_URL")
	if url == "" {
		url = os.Getenv("PROVENANCE_TEST_DB_URL")
	}
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

	u, err := s.CreateUser(ctx, CreateUserParams{
		Username:     "rolecheck-" + uuid.NewString()[:8],
		Email:        uuid.NewString()[:8] + "@rolecheck.test",
		PasswordHash: "x",
		AuthSource:   "oidc",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// The names most products use, which this one does not.
	for _, bad := range []string{"Admin", "Viewer", "administrator", ""} {
		err := s.AssignRoleByName(ctx, u.ID, bad)
		if err == nil {
			t.Errorf("AssignRoleByName(%q) reported success; the user holds no such role "+
				"and nothing said so", bad)
			continue
		}
		if !errors.Is(err, ErrNoSuchRole) {
			t.Errorf("AssignRoleByName(%q) = %v, want ErrNoSuchRole so callers can tell a "+
				"misconfiguration from a database problem", bad, err)
		}
	}

	// A real role still works, and is still idempotent: a user who already holds
	// the role is a no-op success, not an error, because every SSO login re-runs
	// this.
	for i := 0; i < 2; i++ {
		if err := s.AssignRoleByName(ctx, u.ID, "Administrator"); err != nil {
			t.Fatalf("assigning a real role (attempt %d): %v", i+1, err)
		}
	}
	names, err := s.UserRoleNames(ctx, u.ID)
	if err != nil {
		t.Fatalf("read back roles: %v", err)
	}
	if len(names) != 1 || names[0] != "Administrator" {
		t.Errorf("roles after two assignments: %v, want exactly [Administrator]", names)
	}

	// And the configuration-time check answers against the same truth.
	unknown, err := s.UnknownRoleNames(ctx, []string{"Admin", "Operator", "Viewer", "Operator"})
	if err != nil {
		t.Fatalf("UnknownRoleNames: %v", err)
	}
	if len(unknown) != 2 || unknown[0] != "Admin" || unknown[1] != "Viewer" {
		t.Errorf("UnknownRoleNames = %v, want [Admin Viewer] in order, deduplicated", unknown)
	}
}
