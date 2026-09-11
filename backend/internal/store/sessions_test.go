package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ListActiveSessions must show only sessions somebody could still be using.
//
// The bound is the whole point of the query. ListUserSessions, which existed
// first, filters on revoked_at alone -- correct for its callers, which are about
// to end every session they are handed and lose nothing by ending one that had
// already expired. It is wrong for a screen: an expired row is not somebody
// signed in, and an operator reading this list to decide who to cut off would be
// invited to terminate a session that ended by itself days ago, then wonder why
// nothing happened.
//
// Gated on FLEET_STORE_TEST_DB like the other store tests, because the thing
// under test is a WHERE clause and asserting a WHERE clause without a database
// asserts nothing.
func TestListActiveSessionsExcludesEnded(t *testing.T) {
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

	uname := "sesstest-" + uuid.NewString()[:8]
	var userID uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, display_name) VALUES ($1,$2) RETURNING id`,
		uname, "Session Test").Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID)
	})

	mk := func(label string, expires time.Time, revoked bool) uuid.UUID {
		sess, err := s.CreateSession(ctx, userID, "hash-"+label, "10.0.0.9", "ua", true, expires)
		if err != nil {
			t.Fatalf("create session %s: %v", label, err)
		}
		if revoked {
			if err := s.RevokeSession(ctx, sess.ID); err != nil {
				t.Fatalf("revoke %s: %v", label, err)
			}
		}
		return sess.ID
	}

	live := mk("live", time.Now().Add(time.Hour), false)
	expired := mk("expired", time.Now().Add(-time.Hour), false)
	revoked := mk("revoked", time.Now().Add(time.Hour), true)

	got, err := s.ListActiveSessions(ctx, 500)
	if err != nil {
		t.Fatalf("ListActiveSessions: %v", err)
	}
	seen := map[uuid.UUID]ActiveSession{}
	for _, a := range got {
		seen[a.ID] = a
	}

	if _, ok := seen[live]; !ok {
		t.Error("a live session is missing from the list")
	}
	if _, ok := seen[expired]; ok {
		t.Error("an EXPIRED session is listed as active: an operator would be " +
			"offered a session to terminate that ended by itself")
	}
	if _, ok := seen[revoked]; ok {
		t.Error("a REVOKED session is listed as active")
	}

	// The username is the reason this query exists rather than ListUserSessions:
	// a list of session UUIDs is not something an operator can act on.
	if a := seen[live]; a.Username != uname {
		t.Errorf("username = %q, want %q", a.Username, uname)
	}
	if a := seen[live]; a.DisplayName != "Session Test" {
		t.Errorf("displayName = %q, want %q", a.DisplayName, "Session Test")
	}
}
