package monitor

import (
	"errors"
	"testing"
)

// A host that answered anywhere is online, whichever reply arrived last.
//
// keith was getting paired "wap disconnected"/"wap recovered" emails minutes
// apart. The access point was fine: it is probed at three candidate addresses,
// one of which is its bare hostname, and the jump host cannot resolve "wap". That
// dial always failed — and because each failure overwrote an error the success had
// already cleared, the verdict depended on which goroutine replied last.
func TestAHostThatAnsweredIsOnlineWhateverElseFailed(t *testing.T) {
	boom := errors.New(`tunnel to wap:22 via jump: ssh: rejected: connect failed ("Name or service not known")`)

	// Success first, failure after: the ordering that produced the false offline.
	chosen, err := settleProbe([]probeResult{
		{addr: "10.10.0.220", lat: 12},
		{addr: "wap", err: boom},
	}, "")
	if chosen == nil {
		t.Fatalf("reported unreachable although 10.10.0.220 answered (err=%v)", err)
	}
	if chosen.addr != "10.10.0.220" {
		t.Errorf("chose %q", chosen.addr)
	}

	// And the other order, which happened to work before.
	chosen, _ = settleProbe([]probeResult{
		{addr: "wap", err: boom},
		{addr: "10.10.0.220", lat: 12},
	}, "")
	if chosen == nil || chosen.addr != "10.10.0.220" {
		t.Error("the same two answers in the other order gave a different verdict")
	}
}

// Nothing answered: the first error is the reason to show.
func TestWhenNothingAnswersTheReasonSurvives(t *testing.T) {
	first := errors.New("first failure")
	chosen, err := settleProbe([]probeResult{
		{addr: "a", err: first},
		{addr: "b", err: errors.New("second failure")},
	}, "")
	if chosen != nil {
		t.Fatal("chose a candidate that failed")
	}
	if err != first {
		t.Errorf("reason = %v, want the first failure", err)
	}
}

// The overlay address wins when several answer, because reaching a host over the
// overlay is also what proves the overlay is up.
func TestTheOverlayAddressIsPreferred(t *testing.T) {
	chosen, _ := settleProbe([]probeResult{
		{addr: "10.10.0.220", lat: 9},
		{addr: "10.9.0.7", lat: 30},
	}, "10.9.0.7")
	if chosen == nil || chosen.addr != "10.9.0.7" {
		t.Errorf("chose %v, want the overlay address — otherwise a host whose tunnel "+
			"is fine gets reported with wgOk false", chosen)
	}
}
