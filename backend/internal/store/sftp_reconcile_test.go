package store

import (
	"os"
	"strings"
	"testing"
)

// Every other kind of in-flight work is reconciled at startup. File transfers were
// not, and two uploads from June were still "started" in September -- a transfer
// interrupted by a restart never reached a terminal status, so it read as in-flight
// forever in the UI and in every report built from these rows.
func TestTheStartupReconcilerCoversFileTransfers(t *testing.T) {
	src, err := os.ReadFile("../api/server.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "FailStaleSFTPTransfers") {
		t.Error("startup reconciliation does not cover sftp transfers; an interrupted " +
			"transfer will sit at 'started' forever")
	}
}

// ...and it must not touch a live peer's transfer. The predicate is the same one
// every other reconciler uses, applied through the transfer's SESSION because a
// transfer has no instance of its own.
func TestFileTransferReconciliationOnlyTouchesDeadWork(t *testing.T) {
	src, err := os.ReadFile("sftp.go")
	if err != nil {
		t.Fatal(err)
	}
	body := funcBody(string(src), "func (s *Store) FailStaleSFTPTransfers")
	if body == "" {
		t.Fatal("FailStaleSFTPTransfers not found")
	}
	if !strings.Contains(body, "completed_at IS NULL") {
		t.Error("the update is not restricted to in-flight transfers")
	}
	// The three ways a transfer is abandoned, and no fourth.
	for _, want := range []string{"ended_at IS NOT NULL", "NOT EXISTS", `deadOwnerPredicate("s")`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q: a live peer's transfer could be marked interrupted, or a "+
				"genuinely dead one missed", want)
		}
	}
}
