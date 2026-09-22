package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kforbus3/provenance/backend/internal/db"
	"github.com/kforbus3/provenance/backend/internal/models"
)

// Deleting a user must not break the audit chain.
//
// audit_events.actor_id carried ON DELETE SET NULL, and actor_id is part of the
// canonical record the chain hashes. So DELETE /api/v1/users/{id} -- an ordinary
// action behind the User.Delete permission, which is what offboarding somebody is
// -- silently rewrote every event that user had ever produced, and the chain then
// reported broken at the first of them, permanently. The compliance evidence pack
// went with it:
//
//	FAIL - the audit chain is broken at sequence 214
//	Events on or after that point may have been altered or removed and must be
//	investigated before this pack is relied upon as evidence.
//
// The chain was right; rows had been altered. The defect was that the schema let a
// routine administrative act alter them.
//
// Found by deleting a test account during an SSO test, then generating an evidence
// pack for an unrelated reason and reading it.
func TestDeletingAUserDoesNotBreakTheAuditChain(t *testing.T) {
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
	SetAuditHMACKey([]byte("a-test-audit-hmac-key-32-bytes-ok"))
	s := &Store{pool: pool}

	// A user, and some history for them. Two events, so the chain has to carry on
	// past the deleted actor rather than merely end there.
	u, err := s.CreateUser(ctx, CreateUserParams{
		Username:     "offboard-" + uuid.NewString()[:8],
		Email:        uuid.NewString()[:8] + "@offboard.test",
		PasswordHash: "x",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	for _, action := range []string{"auth.login", "certificate.issue"} {
		if _, err := s.AppendAudit(ctx, models.AuditEvent{
			ActorID: &u.ID, ActorName: u.Username, Action: action, TargetKind: "test",
		}); err != nil {
			t.Fatalf("append audit (%s): %v", action, err)
		}
	}
	// And one more from somebody else, so a broken link shows up as a break in the
	// middle rather than at the very end.
	if _, err := s.AppendAudit(ctx, models.AuditEvent{
		ActorName: "someone-else", Action: "auth.login", TargetKind: "test",
	}); err != nil {
		t.Fatalf("append trailing audit: %v", err)
	}

	before, brokenBefore, err := s.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("verify before: %v", err)
	}
	if !before {
		t.Skipf("this database's chain is already broken at %d, so the deletion below "+
			"would prove nothing", brokenBefore)
	}

	// The act that used to do the damage.
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	after, brokenAt, err := s.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("verify after: %v", err)
	}
	if !after {
		t.Errorf("deleting a user broke the audit chain at sequence %d — an audit row "+
			"was rewritten by the deletion, and every compliance evidence pack from "+
			"here on reports the log as possibly altered", brokenAt)
	}

	// The actor_id itself must survive. This is the column the foreign key used to
	// null, and the chain hashes it -- so "the chain still verifies" and "the rows are
	// unchanged" are the same statement here, but only this assertion says which rows
	// and which column. Without it the test would still pass on a future change that
	// dropped attribution in some way the hash does not cover.
	var rows0, withActor int
	if err := pool.QueryRow(ctx,
		`SELECT count(*), count(actor_id) FROM audit_events WHERE actor_name = $1`,
		u.Username).Scan(&rows0, &withActor); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if rows0 == 0 {
		t.Fatalf("no audit rows remain for %q at all", u.Username)
	}
	if withActor != rows0 {
		t.Errorf("%d of %d audit rows for the deleted user lost their actor_id. Deleting an "+
			"account must not rewrite what that account did: the history is evidence about "+
			"the person, and it outlives their access.", rows0-withActor, rows0)
	}

	// And the row still says who did it, which is the whole reason actor_name is
	// stored beside actor_id.
	rows, err := s.ListAudit(ctx, AuditFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	var found bool
	for _, r := range rows {
		if r.ActorName == u.Username {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no audit row still names %q after the user was deleted; the history "+
			"of a departed user has to survive them", u.Username)
	}
}
