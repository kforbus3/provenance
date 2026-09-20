package store

import (
	"os"
	"strings"
	"testing"
)

// An acknowledgement is only worth anything if forging one needs the key.
//
// A detected break is permanent — nothing can make altered rows verify again, and
// anything that did would be the forgery the chain exists to prevent. But a verdict
// that can only ever say BROKEN stops being read, and then a second, real break arrives
// at an indicator everybody has learned to ignore. So a break can be acknowledged:
// investigated, recorded, and reported ever after as reviewed rather than as news,
// while verification carries on past it.
//
// That creates an obvious hole: a party with database write access could insert an
// acknowledgement and make their own tampering stop being reported. The defence is that
// an acknowledgement names the audit event that recorded it, and is honoured ONLY when
// that event is present and verifies as part of the chain — which needs the HMAC key.
//
// This asserts the rule on the source, because the behaviour lives in a database walk:
// what matters is that the honouring is conditional on verified evidence, and that
// nothing in the path rewrites a row.
func TestAcknowledgedBreakRequiresVerifiedEvidence(t *testing.T) {
	src, err := readSource("audit.go")
	if err != nil {
		t.Fatal(err)
	}
	body := funcBody(src, "func (s *Store) VerifyAuditChainDetail")
	if body == "" {
		t.Fatal("VerifyAuditChainDetail not found — this test no longer guards what it claims")
	}

	if !strings.Contains(body, "verifiedEvidence[") {
		t.Error("acknowledgements are honoured without checking that the event recording " +
			"them verifies — anyone with database write access could then silence their " +
			"own tampering by inserting a row")
	}
	// The break must still be reported when its evidence did not verify.
	if !strings.Contains(body, "out.BrokenAtSeq = seq") {
		t.Error("an acknowledgement whose evidence is missing no longer falls back to " +
			"reporting the break")
	}
	// And nothing in verification may write.
	for _, forbidden := range []string{"UPDATE audit_events", "DELETE FROM audit_events", "INSERT INTO audit_events"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("verification performs %q — the chain must never be rewritten to make "+
				"it verify; that is the forgery it exists to detect", forbidden)
		}
	}
}

// Acknowledging repairs nothing: the recorded break stays in the result for ever.
func TestAcknowledgingDoesNotRemoveTheBreakFromTheReport(t *testing.T) {
	src, err := readSource("audit.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(src, "Acknowledged []AcknowledgedBreak") {
		t.Fatal("the result no longer carries acknowledged breaks, so an acknowledged " +
			"break would simply vanish from the report")
	}
	body := funcBody(src, "func (s *Store) AcknowledgeAuditChainBreak")
	if body == "" {
		t.Fatal("AcknowledgeAuditChainBreak not found")
	}
	if strings.Contains(body, "audit_events") {
		t.Error("acknowledging touches audit_events — it must only record that a break " +
			"was investigated, never alter the rows that broke")
	}
}

// readSource reads a file from this package, so the assertions above are made against
// the code that actually ships rather than a copy of it.
func readSource(name string) (string, error) {
	b, err := os.ReadFile(name)
	return string(b), err
}
