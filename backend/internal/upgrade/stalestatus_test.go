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
