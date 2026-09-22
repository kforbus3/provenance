package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kforbus3/provenance/backend/internal/db"
	"github.com/kforbus3/provenance/backend/internal/models"
)

// Enabling audit retention reported the chain as broken, for ever.
//
// Verification walks from prev="" and compares each row's prev_hash to the previous
// row's hash. After pruning, the oldest surviving row still points at a hash that is
// no longer present — an UNLINKED break, which is the signature of rows being removed.
// PruneAuditEventsBefore's own comment claimed "the rows that remain still verify
// forward from the new oldest entry"; measured, pruning two of six rows reported
// intact=false at the first survivor.
//
// That mattered beyond tidiness: retention is the only legitimate way old damaged
// history ever leaves the database, so it traded one permanent warning for another —
// and the new one looked like tampering.
func pruneTestStore(t *testing.T) (context.Context, *Store, *pgxpool.Pool) {
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
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	SetAuditHMACKey([]byte("a-test-audit-hmac-key-32-bytes-ok"))
	s := &Store{pool: pool}
	for _, q := range []string{
		`DELETE FROM audit_chain_prunes`, `DELETE FROM audit_chain_break_ranges`,
		`DELETE FROM audit_chain_breaks`, `DELETE FROM audit_events`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("clear (%s): %v", q, err)
		}
	}
	return ctx, s, pool
}

func appendProbes(t *testing.T, ctx context.Context, s *Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := s.AppendAudit(ctx, models.AuditEvent{Action: "probe.event", TargetKind: "t"}); err != nil {
			t.Fatal(err)
		}
	}
}

// cutoffAfter returns a timestamp just after the nth-oldest retained row.
func cutoffAfter(t *testing.T, ctx context.Context, pool *pgxpool.Pool, skip int) time.Time {
	t.Helper()
	var at time.Time
	if err := pool.QueryRow(ctx,
		`SELECT created_at FROM audit_events ORDER BY seq LIMIT 1 OFFSET $1`, skip).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

// A declared prune leaves a chain that verifies.
func TestADeclaredRetentionPruneDoesNotBreakTheChain(t *testing.T) {
	ctx, s, pool := pruneTestStore(t)
	appendProbes(t, ctx, s, 6)
	if ok, at, err := s.VerifyAuditChain(ctx); err != nil || !ok {
		t.Fatalf("baseline not intact: ok=%v at=%d err=%v", ok, at, err)
	}

	n, err := s.PruneAuditEventsBefore(ctx, cutoffAfter(t, ctx, pool, 2))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("pruned %d rows, want 2", n)
	}

	// Before the boundary is evidenced, the break is still reported — a prune nobody
	// could evidence is indistinguishable from a deletion nobody declared.
	if ok, _, _ := s.VerifyAuditChain(ctx); ok {
		t.Error("an unevidenced prune boundary was honoured; inserting that row is all an " +
			"attacker would need to hide a deletion")
	}

	ev, err := s.AppendAudit(ctx, models.AuditEvent{
		ActorName: "system", Action: "audit.retention_pruned", TargetKind: "audit_chain",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeclareAuditPrune(ctx, ev.Seq); err != nil {
		t.Fatal(err)
	}

	ok, at, err := s.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("a DECLARED retention prune still reports the chain broken at %d. Retention "+
			"is the only legitimate way old history leaves the database; if it cannot be "+
			"done without permanently breaking the chain, it cannot be done at all.", at)
	}
}

// An undeclared deletion of the oldest rows must still break the chain.
func TestAnUndeclaredDeletionStillBreaksTheChain(t *testing.T) {
	ctx, s, pool := pruneTestStore(t)
	appendProbes(t, ctx, s, 6)

	// Delete straight from the table, the way an attacker would.
	var through int64
	if err := pool.QueryRow(ctx, `SELECT seq FROM audit_events ORDER BY seq LIMIT 1 OFFSET 1`).Scan(&through); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_events WHERE seq <= $1`, through); err != nil {
		t.Fatal(err)
	}
	ok, _, err := s.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("rows were deleted from the start of the chain and verification still " +
			"reported it intact")
	}
}

// And a boundary pointing at an event that does not exist accounts for nothing.
func TestAFabricatedBoundaryIsIgnored(t *testing.T) {
	ctx, s, pool := pruneTestStore(t)
	appendProbes(t, ctx, s, 6)
	var through int64
	if err := pool.QueryRow(ctx, `SELECT seq FROM audit_events ORDER BY seq LIMIT 1 OFFSET 1`).Scan(&through); err != nil {
		t.Fatal(err)
	}
	var boundary string
	if err := pool.QueryRow(ctx,
		`SELECT prev_hash FROM audit_events WHERE seq > $1 ORDER BY seq LIMIT 1`, through).Scan(&boundary); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_events WHERE seq <= $1`, through); err != nil {
		t.Fatal(err)
	}
	// The attacker writes a boundary naming an event that was never written.
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_chain_prunes (through_seq, boundary_hash, rows_removed, evidence_seq, cutoff)
		VALUES ($1,$2,2,$3,now())`, through, boundary, through+9999); err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := s.VerifyAuditChain(ctx); ok {
		t.Error("a boundary naming a nonexistent event was honoured, so a deletion could be " +
			"hidden with one INSERT")
	}
}
