package terminal

import (
	"os"
	"strings"
	"testing"
)

// An active terminal was force-closed while somebody was typing in it.
//
// The per-minute touchSession exists so a terminal that is busy but quiet -- someone
// reading output, or watching a tail -- is not reaped at the idle TTL. It wrote with
// r.Context(), and a global 60s request timeout is applied to every route: the
// WebSocket is hijacked so the connection lives on, but the context is dead from
// minute one. Every touch after that failed with "context deadline exceeded" and the
// error was discarded, so with the default 30-minute idle TTL a terminal carrying no
// other HTTP traffic was closed underneath its user.
//
// It was masked by an accident: the terminal page polls host status every 30 seconds
// and each authenticated request touches the session. That mask creates the opposite
// problem -- an idle terminal with an open tab is never reaped, because a status poll
// counts as activity -- so the idle TTL was measuring "tab closed", not "terminal
// idle". Fixing the touch is what makes the TTL mean what it says.
func TestTheKeepAliveOutlivesTheRequestContext(t *testing.T) {
	src, err := os.ReadFile("terminal.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	i := strings.Index(body, "touchSession := func() {")
	if i < 0 {
		t.Fatal("touchSession not found — this test no longer guards what it claims")
	}
	end := strings.Index(body[i:], "\n\t}\n")
	if end < 0 {
		t.Fatal("could not delimit touchSession")
	}
	seg := body[i : i+end]

	if strings.Contains(seg, "TouchSession(ctx") {
		t.Error("the keep-alive writes with the request context, which the 60s route timeout " +
			"kills at minute one — so an active terminal is idle-reaped while in use")
	}
	if !strings.Contains(seg, "touchCtx") {
		t.Error("the keep-alive does not use a context that outlives the request")
	}
	if !strings.Contains(seg, "Log.Warn(") {
		t.Error("a failed keep-alive is silent; the session it was meant to preserve would " +
			"be reaped with nothing said about why")
	}

	// The detached context must be tenant-scoped, or the touch is RLS-denied instead.
	if !strings.Contains(body, "touchCtx := h.d.Auth.TenantScope(context.Background(), p)") {
		t.Error("touchCtx is not built from context.Background() with a tenant scope")
	}
}
