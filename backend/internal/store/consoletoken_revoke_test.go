package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// Signing out must retire the console's token and NOTHING ELSE the operator holds.
//
// This is the test that matters, and the assertion is the kubeconfig token rather
// than the console one. Both are scoped to /api/v1/k8s and both belong to the same
// person, so anything that selects them by scope or by owner destroys the
// credential in the operator's kubectl config every time they sign out of the web
// UI -- and the symptom appears later, somewhere else, as kubectl telling them
// their token is invalid.
func TestSigningOutRetiresOnlyTheConsoleToken(t *testing.T) {
	dsn := os.Getenv("PROV_STORE_TEST_DB")
	if dsn == "" {
		t.Skip("set PROV_STORE_TEST_DB to a Postgres DSN with the schema applied")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	s := &Store{pool: pool}

	u := "console-" + uuid.NewString()[:8]
	var userID uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, display_name) VALUES ($1,'C') RETURNING id`, u,
	).Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM api_tokens WHERE service_account_id=$1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID)
	})

	exp := time.Now().Add(time.Hour)
	mk := func(name string) uuid.UUID {
		tok, err := s.CreateScopedAPIToken(ctx, userID, name,
			uuid.NewString(), uuid.NewString()[:8], userID, &exp, "/api/v1/k8s")
		if err != nil {
			t.Fatalf("mint %q: %v", name, err)
		}
		return tok.ID
	}
	console := mk(models.ConsoleTokenNamePrefix + u)
	kubeconfig := mk("kubeconfig for " + u)
	// A second console token, as an operator who used two browsers would have.
	console2 := mk(models.ConsoleTokenNamePrefix + u)

	n, err := s.RevokeAPITokensByNamePrefix(ctx, userID, models.ConsoleTokenNamePrefix)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if n != 2 {
		t.Errorf("revoked %d tokens, want the 2 console ones", n)
	}

	revoked := func(id uuid.UUID) bool {
		var at *time.Time
		if err := pool.QueryRow(ctx, `SELECT revoked_at FROM api_tokens WHERE id=$1`, id).Scan(&at); err != nil {
			t.Fatalf("read back: %v", err)
		}
		return at != nil
	}
	if !revoked(console) || !revoked(console2) {
		t.Error("a console token survived sign-out, so the browser it is cached in still reaches the cluster")
	}
	if revoked(kubeconfig) {
		t.Error("signing out of the web UI revoked the operator's kubeconfig token")
	}

	// Idempotent: a second sign-out has nothing left to do, and zero is not an
	// error -- a user who never opened the console holds none at all.
	again, err := s.RevokeAPITokensByNamePrefix(ctx, userID, models.ConsoleTokenNamePrefix)
	if err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if again != 0 {
		t.Errorf("second revoke reported %d, want 0", again)
	}
}

// A user's sign-out must not touch anyone else's console token.
func TestRevokingConsoleTokensIsScopedToTheOwner(t *testing.T) {
	dsn := os.Getenv("PROV_STORE_TEST_DB")
	if dsn == "" {
		t.Skip("set PROV_STORE_TEST_DB to a Postgres DSN with the schema applied")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	s := &Store{pool: pool}

	mkUser := func() uuid.UUID {
		var id uuid.UUID
		u := "console-" + uuid.NewString()[:8]
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (username, display_name) VALUES ($1,'C') RETURNING id`, u,
		).Scan(&id); err != nil {
			t.Fatalf("create user: %v", err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(ctx, `DELETE FROM api_tokens WHERE service_account_id=$1`, id)
			_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
		})
		return id
	}
	alice, bob := mkUser(), mkUser()
	exp := time.Now().Add(time.Hour)
	for _, id := range []uuid.UUID{alice, bob} {
		if _, err := s.CreateScopedAPIToken(ctx, id, models.ConsoleTokenNamePrefix+"x",
			uuid.NewString(), uuid.NewString()[:8], id, &exp, "/api/v1/k8s"); err != nil {
			t.Fatalf("mint: %v", err)
		}
	}
	if n, err := s.RevokeAPITokensByNamePrefix(ctx, alice, models.ConsoleTokenNamePrefix); err != nil || n != 1 {
		t.Fatalf("revoke for alice: n=%d err=%v; want exactly her own", n, err)
	}
	var live int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM api_tokens WHERE service_account_id=$1 AND revoked_at IS NULL`, bob,
	).Scan(&live); err != nil {
		t.Fatalf("count bob: %v", err)
	}
	if live != 1 {
		t.Errorf("bob has %d live console tokens after alice signed out, want 1", live)
	}
}
