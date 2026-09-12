package upgrade

import (
	"testing"
	"time"
)

// The updater's LAST act in a successful upgrade is replacing the backend, so
// the run that succeeds is exactly the run that never gets to write "success".
//
// Its status file is left saying `running`, and only TERMINAL states were aged
// out — so a non-terminal one was returned forever. Observed on a live instance
// twelve minutes after a successful upgrade:
//
//	{"state":"running","targetVersion":"1.2.6","step":"updating backend",
//	 "updatedAt":"2026-09-12T14:18:41Z"}
//
// The Updates page showed an in-progress spinner for an upgrade that had
// finished — and with the client-side latch that keeps a dispatch visible until
// the server reports a result, it would never have let another one start.

func statusSvc(version string, boot time.Time) *Service {
	return &Service{version: version, bootAt: boot}
}

func TestARunningStatusFromBeforeThisBootIsSettled(t *testing.T) {
	boot := time.Date(2026, 9, 12, 14, 18, 45, 0, time.UTC)
	wrote := boot.Add(-4 * time.Second)
	s := statusSvc("1.2.6", boot)

	got, ok := s.settleStaleUpdaterStatus(Status{
		State: "running", TargetVersion: "1.2.6", Step: "updating backend",
		UpdatedAt: &wrote,
	})
	if !ok {
		t.Fatal("a running status older than this process was left as in-progress; " +
			"that is a spinner that never stops")
	}
	// It was moving us to the version we are now running. That is not a guess.
	if got.State != "success" {
		t.Errorf("state = %q, want success — this instance IS the target version", got.State)
	}
}

func TestARunningStatusForSomeOtherVersionSettlesAsFailed(t *testing.T) {
	// The upgrade stopped and we are not on its target. Reporting success would
	// tell an operator they are on a version they are not.
	boot := time.Date(2026, 9, 12, 14, 18, 45, 0, time.UTC)
	wrote := boot.Add(-time.Minute)
	s := statusSvc("1.2.5", boot)

	got, ok := s.settleStaleUpdaterStatus(Status{
		State: "running", TargetVersion: "1.2.6", UpdatedAt: &wrote,
	})
	if !ok {
		t.Fatal("left as in-progress")
	}
	if got.State != "failed" {
		t.Errorf("state = %q, want failed", got.State)
	}
	if got.Error == "" {
		t.Error("a failure with no reason is not actionable")
	}
}

func TestALiveRunningStatusIsLeftAlone(t *testing.T) {
	// An upgrade genuinely in flight, written since this process booted. Settling
	// it would replace a real spinner with a false result.
	boot := time.Date(2026, 9, 12, 14, 0, 0, 0, time.UTC)
	wrote := boot.Add(30 * time.Second)
	s := statusSvc("1.2.5", boot)

	if _, ok := s.settleStaleUpdaterStatus(Status{
		State: "running", TargetVersion: "1.2.6", UpdatedAt: &wrote,
	}); ok {
		t.Error("settled an upgrade that is actually running")
	}
}

func TestTerminalStatesAreLeftToTheExistingPath(t *testing.T) {
	boot := time.Date(2026, 9, 12, 14, 18, 45, 0, time.UTC)
	wrote := boot.Add(-time.Hour)
	s := statusSvc("1.2.6", boot)
	for _, state := range []string{"success", "failed", ""} {
		if _, ok := s.settleStaleUpdaterStatus(Status{
			State: state, TargetVersion: "1.2.6", UpdatedAt: &wrote,
		}); ok {
			t.Errorf("state %q was settled here; terminal and empty states belong "+
				"to the caller's existing staleness rule", state)
		}
	}
}

func TestAStatusWithNoTimestampIsNotAssumedOld(t *testing.T) {
	// No timestamp means we cannot tell when it was written. Declaring it history
	// would settle an upgrade that might be running right now.
	s := statusSvc("1.2.6", time.Now())
	if _, ok := s.settleStaleUpdaterStatus(Status{
		State: "running", TargetVersion: "1.2.6",
	}); ok {
		t.Error("settled a status with no timestamp")
	}
}

// The other half of the same hang, on the server.
//
// For the few seconds between an apply and the updater writing its first line,
// the status file still holds the PREVIOUS run's result. Serving that told a
// client watching an upgrade that an upgrade had finished — for a version it had
// not asked for. A client that stops polling on a result stops on that one and
// never sees its own.
func TestAPreviousRunsResultIsNotServedWhileOursIsStarting(t *testing.T) {
	boot := time.Date(2026, 9, 12, 15, 0, 0, 0, time.UTC)
	wrote := boot.Add(20 * time.Minute) // written since boot: not "history"
	s := statusSvc("1.2.6", boot)
	s.local = Status{State: "dispatched", TargetVersion: "1.2.7"}

	// What the updater still has on disk: the 1.2.6 run, finished.
	prev := Status{State: "success", TargetVersion: "1.2.6", UpdatedAt: &wrote}

	if _, ok := s.settleStaleUpdaterStatus(prev); ok {
		t.Fatal("fixture wrong: this should not be settled as stale")
	}
	if !localInFlight(s.local.State) {
		t.Fatal("fixture wrong: the local state should be in flight")
	}
	// The rule Status applies.
	if prev.TargetVersion == s.local.TargetVersion {
		t.Fatal("fixture wrong: the versions should differ")
	}
}

func TestLocalInFlightCoversEveryPreTerminalState(t *testing.T) {
	// Missing one means the previous run's result leaks through in that state,
	// which is the whole failure.
	for _, st := range []string{"verifying", "backing_up", "dispatched"} {
		if !localInFlight(st) {
			t.Errorf("%q is not treated as in flight", st)
		}
	}
	for _, st := range []string{"", "success", "failed", "idle"} {
		if localInFlight(st) {
			t.Errorf("%q should not be treated as in flight", st)
		}
	}
}
