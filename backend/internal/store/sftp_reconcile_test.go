package store

import (
	"os"
	"regexp"
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

// The first version of the reconciler wrote status='interrupted', which the table's
// CHECK constraint forbids: every run raised a violation, the caller swallowed the
// error, and the rows it existed to clean up were still there afterwards.
//
// So the status it writes is checked against the schema that declares it, not against
// memory.
func TestTheTransferStatusItWritesIsAllowedBySchema(t *testing.T) {
	body := funcBody(mustRead(t, "sftp.go"), "func (s *Store) FailStaleSFTPTransfers")
	if body == "" {
		t.Fatal("FailStaleSFTPTransfers not found")
	}
	written := regexp.MustCompile(`SET status='([a-z_]+)'`).FindStringSubmatch(body)
	if written == nil {
		t.Fatal("could not find the status the reconciler writes")
	}

	// The CHECK clause that constrains sftp_transfers.status, wherever it is declared.
	want := regexp.MustCompile(`(?i)CHECK\s*\(\s*status\s+IN\s*\(([^)]*)\)`)
	var allowed string
	for _, name := range migrationFiles(t) {
		src := mustRead(t, "../db/migrations/"+name)
		i := strings.Index(src, "CREATE TABLE sftp_transfers")
		if i < 0 {
			continue
		}
		if m := want.FindStringSubmatch(src[i:]); m != nil {
			allowed = m[1]
			break
		}
	}
	if allowed == "" {
		t.Skip("no CHECK constraint on sftp_transfers.status in the migrations")
	}
	if !strings.Contains(allowed, "'"+written[1]+"'") {
		t.Errorf("the reconciler writes status=%q, which the schema does not allow (%s)", written[1], allowed)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func migrationFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("../db/migrations")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			out = append(out, e.Name())
		}
	}
	return out
}
