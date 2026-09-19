package store

import (
	"strings"
	"testing"
)

// Every schedule on this fleet read "started" forever. last_status records what FIRING
// did and never changes afterwards, so a playbook schedule that failed six nights
// running was indistinguishable from one that worked -- on the page an operator opens
// to find out which. The outcome is derived from the records the firing created.
func TestTheOutcomeCoversEveryKindThatProducesRuns(t *testing.T) {
	sql := lastOutcomeSQL
	// The four kinds that create records. vulndb creates none and must fall through
	// to the ELSE rather than claim a verdict.
	for kind, table := range map[string]string{
		"scan":     "host_scans",
		"playbook": "playbook_runs",
		"vulnscan": "vuln_scans",
		"script":   "winscript_runs",
	} {
		if !strings.Contains(sql, "kind='"+kind+"'") {
			t.Errorf("no outcome branch for kind %q: its schedules will show no verdict", kind)
		}
		if !strings.Contains(sql, table) {
			t.Errorf("kind %q does not read %s", kind, table)
		}
	}
	if !strings.Contains(sql, "ELSE ''") {
		t.Error("a kind that produces no records must fall through to empty, not to a verdict")
	}
}

// Failed must beat in-flight, and in-flight must beat completed. A batch where one
// host failed and the rest finished is a failure to look at, and reading it as
// "completed" is how six consecutive failures went unnoticed.
func TestFailedOutweighsInFlightWhichOutweighsCompleted(t *testing.T) {
	sql := lastOutcomeSQL
	failed := strings.Index(sql, "'failed'")
	running := strings.Index(sql, "'running'")
	completed := strings.Index(sql, "'completed'")
	if failed < 0 || running < 0 || completed < 0 {
		t.Fatal("the three verdicts are not all present")
	}
	if !(failed < running && running < completed) {
		t.Errorf("precedence is wrong (failed@%d running@%d completed@%d): in a CASE the "+
			"first matching branch wins, so a batch with one failure would report otherwise",
			failed, running, completed)
	}
	// Every status that means "it did not work" has to be in the failed set. Each
	// table has its own vocabulary: playbook runs use "interrupted", enrollment uses
	// "rolled_back".
	for _, s := range []string{"'failed'", "'error'", "'cancelled'", "'interrupted'"} {
		if !strings.Contains(sql[failed:running], s) {
			t.Errorf("%s is not counted as a failure", s)
		}
	}
}
