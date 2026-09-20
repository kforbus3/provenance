package upgrade

import (
	"io"
	"log/slog"
	"testing"
)

// discardLogger is a logger that keeps its output to itself.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// A failed upgrade must not leave the instance drained.
//
// Drain is set before dispatch, on the reasoning that the replacement container starts
// un-drained so the state dies with the old one. That holds for an upgrade that
// replaces the container. An upgrade can fail AFTER dispatch and BEFORE anything is
// swapped — a bundle whose rollback anchor cannot be created, an updater that rejects
// the job — and then this very process is still running, drained, with nothing left to
// lift it: /ready keeps failing, the load balancer keeps the instance ejected, and every
// open UI keeps showing "Upgrading — reconnecting shortly" for an upgrade that stopped.
//
// Observed on a QA instance: state=failed, draining=true, serving for ten minutes.
func TestFailedUpgradeLiftsTheDrain(t *testing.T) {
	s := &Service{log: discardLogger()}
	s.SetDrain(true, "Upgrading to 9.9.9")
	if !s.IsDraining() {
		t.Fatal("drain did not take")
	}
	s.fail("the updater could not create a rollback anchor")
	if s.IsDraining() {
		t.Error("the instance is still draining after a failed upgrade — /ready keeps " +
			"failing and the UI keeps showing a maintenance banner, with nothing left " +
			"to lift it but a manual restart")
	}
	if s.local.State != "failed" {
		t.Errorf("state is %q, want failed", s.local.State)
	}
}

// The same, for a failure the UPDATER reports rather than one the backend raised —
// which is the more common shape, since the backend hands off and stops watching.
func TestUpdaterReportedFailureLiftsTheDrain(t *testing.T) {
	s := &Service{log: discardLogger()}
	s.SetDrain(true, "Upgrading")
	s.liftDrainAfterFailure("loading image prov-updater: no such image")
	if s.IsDraining() {
		t.Error("drain survived an updater-reported failure")
	}
	// Idempotent: Status polls this continuously.
	s.liftDrainAfterFailure("same failure again")
	if s.IsDraining() {
		t.Error("drain came back")
	}
}
