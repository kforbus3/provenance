package federation

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A federation link must not run on the request's context.
//
// Every route is behind middleware.Timeout(60s). The link is a hijacked WebSocket that
// outlives that by design — but the context handed to the ingest loop was r.Context(),
// so sixty seconds after a site linked, every database write failed:
//
//	ingest host ... err="context deadline exceeded"
//
// once per push, forever. The link reported "up", the Sites page showed zero lag, and
// the hub's aggregated view stayed empty permanently. Observed on a live pair.
//
// The assertion is on the source, because the failure is a lifetime and there is no
// value to inspect at run time: what matters is that the cancellation is dropped where
// the link context is built.
func TestLinkContextOutlivesTheRequest(t *testing.T) {
	src, err := os.ReadFile("hub.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)

	i := strings.Index(body, "func (s *Service) handleLink")
	if i < 0 {
		t.Fatal("handleLink not found — this test no longer guards what it claims to")
	}
	// The context the link runs on, wherever in the handler it is built.
	built := regexp.MustCompile(`bctx := ([^\n]+)`).FindStringSubmatch(body[i:])
	if built == nil {
		t.Fatal("handleLink no longer builds a bctx — update this test to follow it")
	}
	if !strings.Contains(built[1], "WithoutCancel") {
		t.Errorf("the federation link context is built as %q, which carries the request's "+
			"cancellation. A hijacked WebSocket outlives middleware.Timeout(60s); its "+
			"context must not, or every ingest after the first minute fails with "+
			"\"context deadline exceeded\" while the link still reports healthy.", built[1])
	}
}

// And the behaviour the fix relies on, asserted rather than assumed: WithoutCancel
// keeps values and drops the deadline.
func TestWithoutCancelKeepsValuesAndDropsTheDeadline(t *testing.T) {
	type key struct{}
	parent := context.WithValue(context.Background(), key{}, "site-scope")
	timed, cancel := context.WithTimeout(parent, 10*time.Millisecond)
	defer cancel()

	kept := context.WithoutCancel(timed)
	time.Sleep(30 * time.Millisecond)

	if timed.Err() == nil {
		t.Fatal("the parent did not expire, so this proves nothing")
	}
	if kept.Err() != nil {
		t.Errorf("the derived context expired with its parent: %v", kept.Err())
	}
	if kept.Value(key{}) != "site-scope" {
		t.Error("the derived context lost the request's values — tenant scope travels this way")
	}
}
