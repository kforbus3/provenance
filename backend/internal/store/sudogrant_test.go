package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A time-boxed root grant must stop conferring root the moment it lapses, and
// must reach a host through its groups.
//
// The expiry is the entire reason this exists rather than granting Host.Sudo to a
// role. A grant that outlived its expires_at would be the thing it replaced: a
// permanent escalation, with the added problem of looking temporary.
func TestHasSudoGrant(t *testing.T) {
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

	var userID, hostID, otherHost, groupID uuid.UUID
	must := func(q string, args ...any) uuid.UUID {
		var id uuid.UUID
		if err := pool.QueryRow(ctx, q, args...).Scan(&id); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return id
	}
	u := "sudogrant-" + uuid.NewString()[:8]
	userID = must(`INSERT INTO users (username, display_name) VALUES ($1,'G') RETURNING id`, u)
	hostID = must(`INSERT INTO hosts (hostname, address) VALUES ($1,'10.9.9.1') RETURNING id`, u+"-h1")
	otherHost = must(`INSERT INTO hosts (hostname, address) VALUES ($1,'10.9.9.2') RETURNING id`, u+"-h2")
	groupID = must(`INSERT INTO groups (name) VALUES ($1) RETURNING id`, u+"-grp")
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM temporary_permissions WHERE user_id=$1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM host_groups WHERE group_id=$1`, groupID)
		_, _ = pool.Exec(ctx, `DELETE FROM groups WHERE id=$1`, groupID)
		_, _ = pool.Exec(ctx, `DELETE FROM hosts WHERE id=ANY($1)`, []uuid.UUID{hostID, otherHost})
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID)
	})

	grant := func(host *uuid.UUID, group *uuid.UUID, sudo bool, d time.Duration, revoked bool) {
		var rev any
		if revoked {
			rev = time.Now()
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO temporary_permissions (user_id, host_id, group_id, expires_at, sudo, revoked_at)
			VALUES ($1,$2,$3, now() + make_interval(secs => $4), $5, $6)`,
			userID, host, group, d.Seconds(), sudo, rev)
		if err != nil {
			t.Fatalf("grant: %v", err)
		}
	}
	has := func() bool {
		ok, err := s.HasSudoGrant(ctx, userID, hostID)
		if err != nil {
			t.Fatalf("HasSudoGrant: %v", err)
		}
		return ok
	}

	if has() {
		t.Fatal("no grants at all, yet root was conferred")
	}

	// Access without the sudo flag: on the host, but not root. This is the
	// approver granting the access and withholding the privilege.
	grant(&hostID, nil, false, time.Hour, false)
	if has() {
		t.Error("a non-sudo access grant must not confer root")
	}

	// Expired: the whole point. An hour in the past.
	grant(&hostID, nil, true, -time.Hour, false)
	if has() {
		t.Error("an EXPIRED sudo grant still conferred root — it would be a " +
			"permanent escalation that merely looks temporary")
	}

	// Revoked before expiry.
	grant(&hostID, nil, true, time.Hour, true)
	if has() {
		t.Error("a REVOKED sudo grant still conferred root")
	}

	// For a different host.
	grant(&otherHost, nil, true, time.Hour, false)
	if has() {
		t.Error("a grant for another host conferred root here — grants must be scoped")
	}

	// Live, for this host.
	grant(&hostID, nil, true, time.Hour, false)
	if !has() {
		t.Error("an active sudo grant for this host did not confer root")
	}

	// Through a group the host belongs to.
	_, _ = pool.Exec(ctx, `DELETE FROM temporary_permissions WHERE user_id=$1`, userID)
	if has() {
		t.Fatal("grants were not cleared")
	}
	grant(nil, &groupID, true, time.Hour, false)
	if has() {
		t.Error("a group grant applied before the host was in the group")
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO host_groups (host_id, group_id) VALUES ($1,$2)`, hostID, groupID); err != nil {
		t.Fatalf("add to group: %v", err)
	}
	if !has() {
		t.Error("a sudo grant on a group did not reach a host in that group")
	}
}
