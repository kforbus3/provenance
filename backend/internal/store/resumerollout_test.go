package store

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Resume was a button that reported success and did nothing.
//
// It marked failed hosts `forgiven` — which stops them counting against the
// failure budget — and returned only `applying` hosts to pending. In a PUSH
// engine a host left in `failed` is never picked up again, so the next tick found
// nothing pending, nothing in flight, and marked the rollout completed.
//
// Observed on a live instance. One host, one rollout:
//
//	rollout: completed      host: failed, forgiven=t, attempts=1
//
// Resumed, completed, and not one container updated. The comment inside the
// function it broke says a resume that returns success and does nothing is worse
// than one that refuses.
//
// A round-trip test needs a Postgres. The DB-backed tests here are gated on a DSN
// and skip without one, so this reads the statement — which is enough to catch
// the specific mistake: a resume that does not return failed hosts to pending.
func TestResumeReturnsFailedHostsToPending(t *testing.T) {
	src, err := os.ReadFile("updaterollouts.go")
	if err != nil {
		t.Fatal(err)
	}
	body := funcBody(string(src), "func (s *Store) ResumeUpdateRollout")
	if body == "" {
		t.Fatal("ResumeUpdateRollout not found")
	}

	reset := regexp.MustCompile(`SET\s+state\s*=\s*'pending'`)
	if !reset.MatchString(body) {
		t.Fatal("resume never sets a host back to pending, so nothing is retried")
	}
	// The statement that resets to pending must cover 'failed', not only
	// 'applying'. That distinction IS the bug.
	if !strings.Contains(body, "'failed'") {
		t.Error("resume does not return FAILED hosts to pending — a push engine " +
			"never picks them up again, so the rollout completes having done nothing")
	}
	if !strings.Contains(body, "forgiven = FALSE") {
		t.Error("resume leaves forgiven set, which exempts these hosts from the " +
			"failure budget for the rest of the rollout — one that kept failing " +
			"would never halt again")
	}
	if !strings.Contains(body, "attempts = 0") {
		t.Error("resume does not reset attempts, so a host that used them up has no " +
			"way back even after its cause is fixed")
	}
}

func TestResumeClearsTheHaltReason(t *testing.T) {
	src, _ := os.ReadFile("updaterollouts.go")
	body := funcBody(string(src), "func (s *Store) ResumeUpdateRollout")
	if !strings.Contains(body, "halt_reason = ''") {
		t.Error("a resumed rollout keeps the reason it halted, which reads as though " +
			"it is still halted")
	}
	if !strings.Contains(body, "state = 'running'") {
		t.Error("resume does not set the rollout running")
	}
}

// funcBody returns the source of one function, from its signature to the next
// line that starts a new top-level declaration.
func funcBody(src, sig string) string {
	i := strings.Index(src, sig)
	if i < 0 {
		return ""
	}
	rest := src[i:]
	if j := strings.Index(rest, "\n}\n"); j > 0 {
		return rest[:j]
	}
	return rest
}
