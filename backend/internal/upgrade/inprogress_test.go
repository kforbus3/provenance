package upgrade

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/kforbus3/provenance/backend/internal/config"
)

// svc builds a Service with just enough wiring for the in-progress check: an
// updater URL that resolves to nothing, so updaterStatus reports "cannot tell".
func svc(state string) *Service {
	return &Service{
		cfg:    &config.Config{UpdaterURL: "http://127.0.0.1:1"},
		client: &http.Client{Timeout: 50 * time.Millisecond},
		local:  Status{State: state},
	}
}

// Three applies in sixteen seconds.
//
// The in-progress check lived inside the goroutine the handler spawns, so the
// handler had already returned 202 "applying" and written an audit event before
// anything looked. The second and third clicks were rejected out of sight: the
// operator saw a button that reported success and did nothing, so they clicked
// it again.
//
//	13:34:43  system.upgrade_apply  1.2.4
//	13:34:50  system.upgrade_apply  1.2.4
//	13:34:59  system.upgrade_apply  1.2.4
func TestInProgressBlocksWhileLocalWorkIsRunning(t *testing.T) {
	for _, state := range []string{"verifying", "backing_up"} {
		s := svc(state)
		if !s.InProgress(context.Background()) {
			t.Errorf("state %q: a second apply was allowed while the first was still %s",
				state, state)
		}
	}
}

func TestInProgressAllowsWhenIdle(t *testing.T) {
	for _, state := range []string{"", "idle", "success", "failed"} {
		s := svc(state)
		if s.InProgress(context.Background()) {
			t.Errorf("state %q: refused an apply when nothing was running", state)
		}
	}
}

func TestAStaleDispatchedStateDoesNotBlockForever(t *testing.T) {
	// "dispatched" persists after handing off to the updater. If that updater run
	// then finished or failed, the local state is stale — and treating it as
	// blocking would refuse every future upgrade until the backend restarted,
	// turning a transient handoff into a permanently un-upgradable instance.
	//
	// With no updater reachable, updaterStatus returns !ok and the state is
	// trusted as-is: refusing is the safe direction when we genuinely cannot tell
	// whether something is still running.
	s := svc("dispatched")
	if !s.InProgress(context.Background()) {
		t.Error("with no updater reachable, a dispatched state must be trusted " +
			"rather than assumed stale — starting a second upgrade over a running " +
			"one is the worse mistake")
	}
}
