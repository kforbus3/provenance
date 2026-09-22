package sftp

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// A ten-minute download finished with no record that it had happened.
//
// A global 60s request timeout is applied to every route (api/server.go). Chi's
// Timeout sets a deadline on r.Context(); the handler keeps running, so on any
// transfer longer than a minute:
//
//   - the per-minute keep-alive touch -- which exists precisely so a multi-GB
//     transfer is not idle-reaped mid-flight -- failed with "context deadline
//     exceeded", discarded by a `_`;
//   - the completion record and the audit event written at the end failed the same
//     way, also discarded.
//
// A client that disconnects cancels the same context, so the request context was the
// wrong choice even without the timeout. The RDP handler already did this correctly,
// with a comment explaining why.
//
// Asserted on the source: reproducing it needs a live SSH host and a transfer that
// outlives a minute. What matters is that none of these three writes can reach for
// r.Context() again.
func TestTransferRecordsDoNotUseTheRequestContext(t *testing.T) {
	src, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)

	for _, fn := range []string{
		"func (h *handler) sessionToucher(",
		"func (h *handler) finishTransfer(",
		"func (h *handler) audit(",
	} {
		seg := funcSegment(body, fn)
		if seg == "" {
			t.Fatalf("%s not found — this test no longer guards what it claims", fn)
		}
		if strings.Contains(seg, "r.Context()") {
			t.Errorf("%s writes with the request context. Past the 60s route timeout (or a "+
				"client disconnect) that context is dead, so the write silently does nothing "+
				"— which is how a long transfer completed with no completion record and no "+
				"audit event.", fn)
		}
		if !strings.Contains(seg, "h.detached(") {
			t.Errorf("%s does not use the detached, tenant-scoped context", fn)
		}
	}
}

// Failing to audit a completed transfer must be loud.
//
// The hash chain cannot show a dropped event as a gap: the next row chains from the
// last one that succeeded. So a lost audit write leaves no trace anywhere except the
// log, and a file left a managed host with no record of it.
func TestAMissingTransferAuditIsLogged(t *testing.T) {
	src, _ := os.ReadFile("handlers.go")
	body := string(src)
	for _, fn := range []string{"func (h *handler) audit(", "func (h *handler) finishTransfer("} {
		seg := funcSegment(body, fn)
		if !regexp.MustCompile(`h\.d\.Log\.(Error|Warn)\(`).MatchString(seg) {
			t.Errorf("%s ignores its write error without logging. The chain cannot reveal a "+
				"dropped event, so nothing would ever surface it.", fn)
		}
	}
}

// And the detached context must still be tenant-scoped, or the write it was created
// to save is refused by row-level security instead of by the deadline.
func TestTheDetachedContextIsTenantScoped(t *testing.T) {
	src, _ := os.ReadFile("handlers.go")
	seg := funcSegment(string(src), "func (h *handler) detached(")
	if seg == "" {
		t.Fatal("detached() not found")
	}
	if !strings.Contains(seg, "TenantScope(") {
		t.Error("the detached context is not tenant-scoped; under multi-tenancy the write " +
			"would be RLS-denied — a different silent failure with the same symptom")
	}
	if !strings.Contains(seg, "context.Background()") {
		t.Error("the detached context still derives from the request")
	}
}

func funcSegment(src, sig string) string {
	i := strings.Index(src, sig)
	if i < 0 {
		return ""
	}
	rest := src[i:]
	if end := strings.Index(rest, "\n}\n"); end > 0 {
		return rest[:end]
	}
	return rest
}
