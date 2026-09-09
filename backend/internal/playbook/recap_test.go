package playbook

import (
	"os"
	"strings"
	"testing"
)

// The alert this replaces named all thirteen hosts a run targeted and gave
// ansible's exit code as the reason, which is how a run where twelve hosts
// updated cleanly and one machine was switched off produced an alert that could
// not be acted on without opening the run and reading to the bottom.

// The genuine article: the stored output of the run that actually sent the
// alert. Synthetic fixtures agree with whatever the parser happens to do; this
// one does not, and it is the reason the parser handles the padding, the
// interleaved WARNING blocks and the trailing whitespace that it does.
func realRun(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/apt-cache-imager-unreachable.txt")
	if err != nil {
		t.Fatalf("reading the recorded run: %v", err)
	}
	return string(b)
}

func TestSummaryNamesOnlyTheHostThatFailed(t *testing.T) {
	targets := []string{"ai", "coder", "containers", "debian", "docker", "gitlab",
		"grafana", "imager", "mcp", "prometheus", "python", "repo", "tvadblocker"}
	got := failureSummary(realRun(t), targets, "ansible-playbook exited 2")

	if !strings.Contains(got, "imager (unreachable)") {
		t.Errorf("does not name the host that failed, or why:\n  %s", got)
	}
	if !strings.Contains(got, "The other 12 hosts succeeded") {
		t.Errorf("does not say the rest were fine:\n  %s", got)
	}
	// The whole point: the twelve healthy hosts must not appear. Naming them is
	// what made the old alert unreadable.
	for _, h := range []string{"prometheus", "grafana", "tvadblocker", "repo"} {
		if strings.Contains(got, h) {
			t.Errorf("names %s, which succeeded:\n  %s", h, got)
		}
	}
}

func TestTitleCarriesThePlaybookAndTheHost(t *testing.T) {
	// The title becomes the email subject, so it is the only part read without
	// opening anything. Every failure used to arrive as "Playbook run failed".
	got := failureTitle("Update Apt Package Cache", realRun(t))
	if !strings.Contains(got, "Update Apt Package Cache") || !strings.Contains(got, "imager") {
		t.Errorf("subject does not identify the playbook and the host: %q", got)
	}
}

// Unreachable and failed are different problems with different fixes — a host
// that is off, versus a host that ran the play and it did not work. A summary
// that calls both "failed" throws away the more useful half.
func TestUnreachableIsDistinguishedFromFailedTasks(t *testing.T) {
	out := `PLAY RECAP *********************************************************************
gone                       : ok=0    changed=0    unreachable=1    failed=0
broken                     : ok=1    changed=0    unreachable=0    failed=1
fine                       : ok=2    changed=1    unreachable=0    failed=0
`
	got := failureSummary(out, nil, "ansible-playbook exited 2")
	if !strings.Contains(got, "gone (unreachable)") {
		t.Errorf("lost the unreachable distinction: %s", got)
	}
	if !strings.Contains(got, "broken (1 task failed)") {
		t.Errorf("lost the task-failure distinction: %s", got)
	}
}

// A rescued task is the playbook working as designed. Reporting it as a failure
// would alert on plays that handled their own errors, which trains people to
// ignore the alerts.
func TestRescuedAndIgnoredAreNotFailures(t *testing.T) {
	out := `PLAY RECAP *********************************************************************
app1                       : ok=5    changed=1    unreachable=0    failed=0    skipped=0    rescued=1    ignored=2
`
	got := failureSummary(out, nil, "ansible-playbook exited 2")
	if strings.Contains(got, "Failed on app1") {
		t.Errorf("treated a rescued task as a host failure: %s", got)
	}
	if !strings.Contains(got, "not specific to a host") {
		t.Errorf("should say the failure was not per-host: %s", got)
	}
}

// No recap means ansible never got far enough to print one — a syntax error, a
// dead runner, a timeout mid-play. "No hosts marked bad" must not be reported
// as "no hosts had problems"; the honest answer is that it is not known.
func TestNoRecapSaysSoRatherThanGuessing(t *testing.T) {
	out := "ERROR! the playbook could not be parsed\n"
	got := failureSummary(out, []string{"a", "b"}, "ansible-playbook exited 4")
	if !strings.Contains(got, "no play recap") {
		t.Errorf("did not admit the recap was missing: %s", got)
	}
	if strings.Contains(got, "succeeded") {
		t.Errorf("claimed something about hosts it cannot know: %s", got)
	}
}

// A broken change against a large fleet fails everywhere. An email listing
// every name is the same wall of text this replaces.
func TestManyFailuresAreCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString("PLAY RECAP ****\n")
	for i := 0; i < 40; i++ {
		b.WriteString("host" + string(rune('a'+i%26)) + string(rune('0'+i/26)) +
			" : ok=0 changed=0 unreachable=1 failed=0\n")
	}
	got := failureSummary(b.String(), nil, "exited 2")
	if !strings.Contains(got, "more") {
		t.Errorf("did not cap the host list: %s", got)
	}
	if len(got) > 400 {
		t.Errorf("summary is %d chars; too long for an alert:\n%s", len(got), got)
	}
	if title := failureTitle("Big Rollout", b.String()); !strings.Contains(title, "40 hosts") {
		t.Errorf("subject should count rather than list: %q", title)
	}
}

// Ansible enables colour by itself in some configurations. An escape sequence
// swallowed into a hostname would end up in an email subject line.
func TestAnsiColourDoesNotLeakIntoNames(t *testing.T) {
	out := "PLAY RECAP ****\n\x1b[0;31mimager\x1b[0m                 : ok=0    changed=0    unreachable=1    failed=0\n"
	r := parseRecap(out)
	if len(r) != 1 || r[0].Host != "imager" {
		t.Fatalf("parsed %+v, want a single clean host named imager", r)
	}
}

// Older and newer ansible print different trailing counters. Requiring the ones
// that have always been there keeps this working across upgrades of the runner
// image, which is not something anyone would think to re-test.
func TestRecapParsesWithoutTheOptionalCounters(t *testing.T) {
	out := "PLAY RECAP ****\nweb1 : ok=3 changed=2 unreachable=0 failed=1\n"
	r := parseRecap(out)
	if len(r) != 1 || r[0].Failed != 1 {
		t.Fatalf("parsed %+v, want one host with failed=1", r)
	}
}
