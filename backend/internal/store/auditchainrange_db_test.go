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

// A bulk acknowledgement is the most dangerous thing in this package.
//
// Acknowledging thousands of breaks in one action is necessary — the foreign key
// dropped in 0106 broke 3,054 of 5,521 rows in the first production chain examined
// after the fix, and acknowledging those one at a time is 3,054 attestations that
// each append an audit event — but it is also exactly the tool somebody would want in
// order to make their own alteration stop being reported. So every test here is an
// attempt to hide a real alteration inside a legitimate acknowledgement, and each one
// must fail.

func rangeTestStore(t *testing.T) (context.Context, *Store, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("PROV_TEST_DATABASE_URL")
	if url == "" {
		url = os.Getenv("PROVENANCE_TEST_DB_URL")
	}
	if url == "" {
		t.Skip("no test database offered; run via `make test-db`")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	SetAuditHMACKey([]byte("a-test-audit-hmac-key-32-bytes-ok"))
	// Start from an empty chain so assertions are about this test's rows.
	for _, q := range []string{
		`DELETE FROM audit_chain_break_ranges`,
		`DELETE FROM audit_chain_breaks`,
		`DELETE FROM audit_events`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("clear (%s): %v", q, err)
		}
	}
	return ctx, &Store{pool: pool}, pool
}

// appendN writes n events attributed to a real user and returns their sequences.
func appendN(t *testing.T, ctx context.Context, s *Store, n int) (uuid.UUID, []int64) {
	t.Helper()
	u, err := s.CreateUser(ctx, CreateUserParams{
		Username:     "range-" + uuid.NewString()[:8],
		Email:        uuid.NewString()[:8] + "@range.test",
		PasswordHash: "x",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	var seqs []int64
	for i := 0; i < n; i++ {
		ev, err := s.AppendAudit(ctx, models.AuditEvent{
			ActorID: &u.ID, ActorName: u.Username, Action: "auth.login", TargetKind: "test",
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		seqs = append(seqs, ev.Seq)
	}
	return u.ID, seqs
}

// nullActor reproduces what the pre-0106 foreign key did on user deletion: the
// actor_id column, which the hash covers, silently becomes NULL.
func nullActor(t *testing.T, ctx context.Context, pool *pgxpool.Pool, seqs ...int64) {
	t.Helper()
	for _, seq := range seqs {
		if _, err := pool.Exec(ctx, `UPDATE audit_events SET actor_id = NULL WHERE seq = $1`, seq); err != nil {
			t.Fatalf("null actor at %d: %v", seq, err)
		}
	}
}

// ackRangeThrough records a range acknowledgement the way the API does: a chained
// audit event first, whose sequence is the evidence the record points at.
func ackRangeThrough(t *testing.T, ctx context.Context, s *Store, from, to int64, covered int) {
	t.Helper()
	if _, err := s.AppendAudit(ctx, models.AuditEvent{
		Action: "audit.chain_break_range_acknowledged", TargetKind: "audit_chain",
	}); err != nil {
		t.Fatalf("append evidence: %v", err)
	}
	evidence, err := s.LatestAuditSeq(ctx)
	if err != nil {
		t.Fatalf("latest seq: %v", err)
	}
	if err := s.AcknowledgeAuditChainRange(ctx, from, to, covered, evidence, nil,
		"tester", "deleted accounts nulled actor_id before 0106"); err != nil {
		t.Fatalf("acknowledge range: %v", err)
	}
}

// The ordinary case: one event broke many rows, one acknowledgement accounts for
// them, and verification carries on past them.
func TestRangeAcknowledgementAccountsForTheBreaksItCovers(t *testing.T) {
	ctx, s, pool := rangeTestStore(t)
	_, seqs := appendN(t, ctx, s, 5)
	nullActor(t, ctx, pool, seqs...)

	res, err := s.VerifyAuditChainDetail(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.BrokenAtSeq != seqs[0] {
		t.Fatalf("expected the chain to break at %d, got %d", seqs[0], res.BrokenAtSeq)
	}

	ackRangeThrough(t, ctx, s, seqs[0], seqs[4], 5)

	res, err = s.VerifyAuditChainDetail(ctx)
	if err != nil {
		t.Fatalf("verify after ack: %v", err)
	}
	if res.BrokenAtSeq != 0 {
		t.Errorf("the chain still reports an unacknowledged break at %d after the range "+
			"covering %d..%d was acknowledged", res.BrokenAtSeq, seqs[0], seqs[4])
	}
	// Repaired nothing: the breaks are still reported, with their count.
	if len(res.AcknowledgedRanges) != 1 {
		t.Fatalf("expected 1 acknowledged range in the report, got %d", len(res.AcknowledgedRanges))
	}
	if got := res.AcknowledgedRanges[0].Covered; got != 5 {
		t.Errorf("the report says the range covers %d breaks, want 5 — an acknowledgement "+
			"that hides how much is broken is worse than none", got)
	}
}

// The attack: alter a row's content, leave its actor id intact, and acknowledge a
// range around it. Losing an actor id is the only thing a range may excuse.
func TestRangeAcknowledgementDoesNotCoverARowThatKeptItsActor(t *testing.T) {
	ctx, s, pool := rangeTestStore(t)
	_, seqs := appendN(t, ctx, s, 5)
	nullActor(t, ctx, pool, seqs[0], seqs[1], seqs[3], seqs[4])
	// seqs[2] keeps its actor and has its recorded detail rewritten instead.
	if _, err := pool.Exec(ctx,
		`UPDATE audit_events SET detail = '{"note":"nothing to see here"}'::jsonb WHERE seq = $1`,
		seqs[2]); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	ackRangeThrough(t, ctx, s, seqs[0], seqs[4], 5)

	res, err := s.VerifyAuditChainDetail(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.BrokenAtSeq != seqs[2] {
		t.Errorf("an altered row inside an acknowledged range was not reported: "+
			"brokenAtSeq=%d, want %d. A range acknowledgement may only excuse a missing "+
			"actor id; this row kept its actor and had its contents rewritten",
			res.BrokenAtSeq, seqs[2])
	}
}

// The attack: remove a row and acknowledge a range over the gap. A missing column
// breaks one row's own hash; a missing ROW breaks the link, and that is never
// coverable in bulk.
func TestRangeAcknowledgementDoesNotCoverABrokenLink(t *testing.T) {
	ctx, s, pool := rangeTestStore(t)
	_, seqs := appendN(t, ctx, s, 5)
	// Every row also loses its actor id, so a missing actor cannot be the reason the
	// removal is caught. The broken LINK has to be the reason, which is the point.
	nullActor(t, ctx, pool, seqs...)
	if _, err := pool.Exec(ctx, `DELETE FROM audit_events WHERE seq = $1`, seqs[2]); err != nil {
		t.Fatalf("delete row: %v", err)
	}

	ackRangeThrough(t, ctx, s, seqs[0], seqs[4], 5)

	res, err := s.VerifyAuditChainDetail(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.BrokenAtSeq != seqs[3] {
		t.Errorf("a removed row inside an acknowledged range was not reported: "+
			"brokenAtSeq=%d, want %d (the row whose prev_hash no longer links). Losing a "+
			"column breaks one row's own hash; losing a ROW breaks the link, and a bulk "+
			"acknowledgement must never excuse that",
			res.BrokenAtSeq, seqs[3])
	}
}

// The attack: acknowledge a wide range now, then alter something inside it later and
// let the standing acknowledgement absorb it. The pinned count is what stops that.
func TestRangeAcknowledgementStopsBeingHonouredWhenANewBreakAppearsInside(t *testing.T) {
	ctx, s, pool := rangeTestStore(t)
	_, seqs := appendN(t, ctx, s, 6)
	nullActor(t, ctx, pool, seqs[0], seqs[1])

	// Acknowledged when two rows inside the span were broken.
	ackRangeThrough(t, ctx, s, seqs[0], seqs[5], 2)
	if res, err := s.VerifyAuditChainDetail(ctx); err != nil || res.BrokenAtSeq != 0 {
		t.Fatalf("baseline: expected an intact verdict after the acknowledgement, got %d (err %v)",
			res.BrokenAtSeq, err)
	}

	// Later, a third row inside the same span loses its actor id.
	nullActor(t, ctx, pool, seqs[4])

	res, err := s.VerifyAuditChainDetail(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.BrokenAtSeq == 0 {
		t.Error("a break that appeared inside an already-acknowledged range was absorbed " +
			"by it silently — the acknowledgement covered more rows than were investigated, " +
			"which makes it a standing licence to alter anything in the span")
	}
	if len(res.AcknowledgedRanges) != 0 {
		t.Errorf("the range is still reported as honoured (%d) while covering more breaks "+
			"than its recorded count", len(res.AcknowledgedRanges))
	}
}

// The attack from 0105, now against a range: insert the acknowledgement straight into
// the database. Without the HMAC key the chained event it points at cannot be forged,
// so it must account for nothing.
func TestRangeAcknowledgementInsertedDirectlyAccountsForNothing(t *testing.T) {
	ctx, s, pool := rangeTestStore(t)
	_, seqs := appendN(t, ctx, s, 4)
	nullActor(t, ctx, pool, seqs...)

	// evidence_seq names a sequence that does not exist, which is the best an attacker
	// without the key can do.
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_chain_break_ranges (from_seq, to_seq, covered_count, evidence_seq, acknowledged_name, note)
		VALUES ($1,$2,$3,$4,'attacker','nothing to see here')`,
		seqs[0], seqs[3], 4, seqs[3]+9999); err != nil {
		t.Fatalf("insert range: %v", err)
	}

	res, err := s.VerifyAuditChainDetail(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.BrokenAtSeq != seqs[0] {
		t.Errorf("a range acknowledgement written straight into the database silenced the "+
			"breaks it claimed: brokenAtSeq=%d, want %d. It is honoured only while the "+
			"chained event recording it verifies, which needs the key",
			res.BrokenAtSeq, seqs[0])
	}
	if len(res.AcknowledgedRanges) != 0 {
		t.Errorf("an unsupported range is reported as honoured (%d)", len(res.AcknowledgedRanges))
	}
}

// The scan must recognise a lost actor id on a row that never had an actor NAME.
//
// The fingerprint first required both a NULL actor_id and a non-empty actor_name, on
// the reasoning that system and CLI rows have neither. host.enroll and
// host.enroll_failed record an actor_id and no actor_name at all, so losing the id
// left them with neither: 136 of 3,054 breaks in production were reported as having
// no known cause when their cause was identical to the other 2,918.
func TestScanRecognisesALostActorOnARowWithNoActorName(t *testing.T) {
	ctx, s, pool := rangeTestStore(t)
	u, err := s.CreateUser(ctx, CreateUserParams{
		Username:     "noname-" + uuid.NewString()[:8],
		Email:        uuid.NewString()[:8] + "@noname.test",
		PasswordHash: "x",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	// Exactly how enrollment records it: an actor id, no actor name.
	ev, err := s.AppendAudit(ctx, models.AuditEvent{
		ActorID: &u.ID, Action: "host.enroll_failed", TargetKind: "host",
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	nullActor(t, ctx, pool, ev.Seq)

	scan, err := s.ScanAuditChain(ctx)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if scan.BreakCount != 1 {
		t.Fatalf("expected 1 break, got %d", scan.BreakCount)
	}
	if scan.LostAttributionCount != 1 {
		t.Errorf("a row that lost its actor_id but never had an actor_name was not "+
			"recognised as such (%d of %d): it would be reported as a break with no known "+
			"cause, sending an operator looking for tampering that did not happen",
			scan.LostAttributionCount, scan.BreakCount)
	}
	if scan.UnlinkedCount != 0 {
		t.Errorf("a lost column reported as a broken link (%d): that would say rows were "+
			"removed or reordered when none were", scan.UnlinkedCount)
	}
}
