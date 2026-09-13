package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// Can a party with only DATABASE WRITE ACCESS append audit rows that the chain
// still reports as intact?
//
// That is the exact threat the keyed chain exists for. The security guide states
// it: "An attacker (including an insider with DB access) must not be able to
// silently alter the record of what happened."
//
// VerifyAuditChain re-derives each row using the algorithm named by that row's
// OWN hash_alg column: hash_alg=2 is HMAC-SHA256 under the server key, anything
// else is plain keyless SHA-256, kept so rows written before the key existed
// still verify. The attacker chooses the column value.
func TestAuditChainRejectsKeylessRowAfterKeying(t *testing.T) {
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

	// A throwaway database: start from an empty chain so the assertion is about
	// this test's rows and not whatever a previous run left behind.
	if _, err := pool.Exec(ctx, `DELETE FROM audit_events`); err != nil {
		t.Fatalf("clear chain: %v", err)
	}

	SetAuditHMACKey([]byte("0123456789012345678901234567890123456789"))
	t.Cleanup(func() { SetAuditHMACKey(nil) })

	// A genuine, keyed event.
	if _, err := s.AppendAudit(ctx, models.AuditEvent{Action: "genuine.event"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if ok, at, err := s.VerifyAuditChain(ctx); err != nil || !ok {
		t.Fatalf("baseline chain not intact: ok=%v at=%d err=%v", ok, at, err)
	}

	// The attacker: reads the tail (plain SELECT), then appends a row of their own
	// choosing, tagged hash_alg=1 and hashed with keyless SHA-256. No key needed.
	var prev string
	if err := pool.QueryRow(ctx,
		`SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&prev); err != nil {
		t.Fatalf("read tail: %v", err)
	}
	detail, _ := json.Marshal(map[string]any{})
	canonical := auditCanonicalLegacy("", "", "attacker.forged", "", "", "", detail)
	sum := sha256.Sum256([]byte(prev + "|" + canonical))
	forged := hex.EncodeToString(sum[:])

	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_events (actor_id, actor_name, action, target_kind, target_id,
		                          ip, detail, prev_hash, hash, hash_alg)
		VALUES (NULL, NULL, 'attacker.forged', '', '', NULL, '{}'::jsonb, $1, $2, 1)`,
		prev, forged); err != nil {
		t.Fatalf("forge insert: %v", err)
	}

	res, err := s.VerifyAuditChainDetail(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// The hashes all line up -- that is the point. The forged row is correctly
	// hashed for the algorithm it claims, so nothing was "altered"; what is wrong
	// is that the tail can be rewritten at will from here.
	if res.BrokenAtSeq != 0 {
		t.Errorf("reported an alteration at seq %d; the forged row's hash is valid "+
			"for the algorithm it claims, so this should be a weak link, not a break",
			res.BrokenAtSeq)
	}
	if res.WeakFromSeq == 0 {
		t.Fatal("A FORGED ROW PASSED UNREPORTED. With the key configured, a party " +
			"holding only database write access appended an audit event tagged " +
			"hash_alg=1, hashed it with plain SHA-256, and the chain reported nothing " +
			"— because verification trusts the algorithm the attacker names. The same " +
			"move rebuilds a whole tail, erasing what it replaces.")
	}
	t.Logf("weak link correctly reported from seq %d (%d row(s))", res.WeakFromSeq, res.WeakCount)
}
