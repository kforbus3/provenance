package pacing

import (
	"testing"
	"time"
)

func TestCanaryGoesFirstAndAlone(t *testing.T) {
	s := Strategy{Canary: 2, BatchSize: 10}
	if got := Capacity(s, 0, 0, nil, time.Now()); got != 2 {
		t.Errorf("nothing started yet: capacity = %d, want 2 (the canaries)", got)
	}
	if got := Capacity(s, 2, 0, nil, time.Now()); got != 0 {
		t.Errorf("both canaries in flight: capacity = %d, want 0", got)
	}
	// One canary has failed rather than verified. The batch phase must not be
	// reached: a rollout that proceeds past a failed canary has no canary at all.
	if got := Capacity(s, 0, 1, nil, time.Now()); got != 1 {
		t.Errorf("one verified, one still to prove: capacity = %d, want 1", got)
	}
}

func TestTheSoakGatesTheFleetNotEachBatch(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	s := Strategy{Canary: 1, BatchSize: 5, SoakSeconds: 600}

	// Canary verified but the phase has not been stamped: nothing may start.
	if got := Capacity(s, 0, 1, nil, now); got != 0 {
		t.Errorf("capacity = %d before the canary phase was stamped, want 0", got)
	}
	done := now
	if got := Capacity(s, 0, 1, &done, now.Add(5*time.Minute)); got != 0 {
		t.Errorf("capacity = %d during the soak, want 0", got)
	}
	if got := Capacity(s, 0, 1, &done, now.Add(11*time.Minute)); got != 5 {
		t.Errorf("capacity = %d after the soak, want 5", got)
	}
	// And it stays open. Measuring the soak from the most recent verification
	// instead would re-arm it on every batch, so a large fleet never finishes.
	if got := Capacity(s, 0, 9, &done, now.Add(4*time.Hour)); got != 5 {
		t.Errorf("capacity = %d well past the soak, want 5", got)
	}
}

func TestNoCanaryMeansNoSoak(t *testing.T) {
	// A soak with no canary has nothing to soak. Gating on it would stall a
	// rollout forever, because canaryDoneAt is never stamped.
	s := Strategy{Canary: 0, BatchSize: 3, SoakSeconds: 3600}
	if got := Capacity(s, 0, 0, nil, time.Now()); got != 3 {
		t.Errorf("capacity = %d, want 3", got)
	}
}

func TestBatchSizeIsAtLeastOne(t *testing.T) {
	// An unset batch size must not mean a rollout that can never start anything.
	for _, b := range []int{0, -1} {
		if got := Capacity(Strategy{BatchSize: b}, 0, 0, nil, time.Now()); got != 1 {
			t.Errorf("BatchSize %d: capacity = %d, want 1", b, got)
		}
	}
}

func TestBudgetOfZeroIsUnlimited(t *testing.T) {
	// The trap: reading `failures > MaxFailures` as the whole rule makes a budget
	// of zero halt on the first failure, turning "no limit" into "no tolerance"
	// for every operator who left the field alone.
	if BudgetExceeded(Strategy{MaxFailures: 0}, 99) {
		t.Error("a budget of 0 halted; 0 means unlimited")
	}
	if BudgetExceeded(Strategy{MaxFailures: 2}, 1) {
		t.Error("halted below the budget")
	}
	if !BudgetExceeded(Strategy{MaxFailures: 2}, 2) {
		t.Error("did not halt at the budget")
	}
}

func TestWindowGatesByTimeOfDay(t *testing.T) {
	w := &Window{Start: "09:00", End: "17:00"}
	at := func(h, m int) time.Time { return time.Date(2026, 9, 12, h, m, 0, 0, time.UTC) }
	if InWindow(w, at(8, 59)) {
		t.Error("permitted work before the window opened")
	}
	if !InWindow(w, at(9, 0)) {
		t.Error("refused at the moment the window opened")
	}
	if InWindow(w, at(17, 0)) {
		t.Error("permitted work at the closing minute; the end is exclusive")
	}
}

func TestAWrappingWindowCoversTheSmallHoursAndNothingElse(t *testing.T) {
	// The bug this shape invites: without the `minutes < end` test, every moment
	// before the start hour falls through to "was yesterday allowed", which with
	// no day restriction is always true -- so a 22:00-04:00 window silently
	// permits updates at any hour, invisible until a machine reboots at noon.
	w := &Window{Start: "22:00", End: "04:00"}
	at := func(h int) time.Time { return time.Date(2026, 9, 12, h, 0, 0, 0, time.UTC) }
	for _, h := range []int{22, 23} {
		if !InWindow(w, at(h)) {
			t.Errorf("refused at %02d:00, inside the window", h)
		}
	}
	if !InWindow(w, at(1)) {
		t.Error("refused at 01:00, inside the window")
	}
	for _, h := range []int{4, 12, 18, 21} {
		if InWindow(w, at(h)) {
			t.Errorf("permitted work at %02d:00, outside the window", h)
		}
	}
}

func TestAWrappingWindowBelongsToTheDayItStartedOn(t *testing.T) {
	// "Saturday 22:00-04:00" must permit 01:00 on SUNDAY -- that is still the
	// Saturday window -- and must not permit 01:00 on Saturday, which belongs to
	// Friday's window and was not allowed.
	w := &Window{Start: "22:00", End: "04:00", Days: []int{int(time.Saturday)}}
	sat23 := time.Date(2026, 9, 12, 23, 0, 0, 0, time.UTC) // a Saturday
	sun01 := time.Date(2026, 9, 13, 1, 0, 0, 0, time.UTC)
	sat01 := time.Date(2026, 9, 12, 1, 0, 0, 0, time.UTC)
	if sat23.Weekday() != time.Saturday {
		t.Fatalf("fixture is not a Saturday: %s", sat23.Weekday())
	}
	if !InWindow(w, sat23) {
		t.Error("refused Saturday 23:00")
	}
	if !InWindow(w, sun01) {
		t.Error("refused Sunday 01:00, which is still Saturday's window")
	}
	if InWindow(w, sat01) {
		t.Error("permitted Saturday 01:00, which belongs to Friday's window")
	}
}

func TestAnUnparseableWindowDoesNotStopEverythingForever(t *testing.T) {
	// A typo in a time field must not be a rollout that can never run and never
	// says why. The window not applying is recoverable; a silent permanent stall
	// is not.
	for _, w := range []*Window{
		{Start: "not a time", End: "04:00"},
		{Start: "22:00", End: "99:99"},
	} {
		if !InWindow(w, time.Now()) {
			t.Errorf("an unparseable window %+v blocked the rollout", w)
		}
	}
	if !InWindow(nil, time.Now()) {
		t.Error("no window should mean no restriction")
	}
}

func TestParseHMRejectsOutOfRange(t *testing.T) {
	for _, s := range []string{"24:00", "22:60", "-1:00", "abc"} {
		if _, err := ParseHM(s); err == nil {
			t.Errorf("ParseHM(%q) accepted an invalid time", s)
		}
	}
	if got, err := ParseHM("22:30"); err != nil || got != 22*60+30 {
		t.Errorf("ParseHM(22:30) = %d, %v", got, err)
	}
}

func TestImageCanariesCappedByHosts(t *testing.T) {
	s := Strategy{Canary: 2}
	if got := ImageCanaries(s, ImageProgress{Hosts: 1}); got != 1 {
		t.Fatalf("got %d", got)
	}
	if got := ImageCanaries(s, ImageProgress{Hosts: 5}); got != 2 {
		t.Fatalf("got %d", got)
	}
	if got := ImageCanaries(Strategy{Canary: -1}, ImageProgress{Hosts: 5}); got != 0 {
		t.Fatalf("got %d", got)
	}
}

func TestImageAdmitsPhases(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	s := Strategy{Canary: 1, BatchSize: 5, SoakSeconds: 300}
	done := now.Add(-2 * time.Minute)
	soaked := now.Add(-6 * time.Minute)
	cases := []struct {
		name string
		p    ImageProgress
		want bool
	}{
		{"canary slot free", ImageProgress{Hosts: 3}, true},
		{"canary in flight", ImageProgress{Hosts: 3, Flying: 1}, false},
		{"soaking", ImageProgress{Hosts: 3, Verified: 1, CanaryDoneAt: &done}, false},
		{"soak over but not re-checked", ImageProgress{Hosts: 3, Verified: 1, CanaryDoneAt: &soaked}, false},
		{"soak over and re-checked", ImageProgress{Hosts: 3, Verified: 1, CanaryDoneAt: &soaked, SoakChecked: true}, true},
		{"verified but never stamped", ImageProgress{Hosts: 3, Verified: 1}, false},
	}
	for _, c := range cases {
		if got := ImageAdmits(s, c.p, now); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	// No soak: verified canaries are enough.
	if !ImageAdmits(Strategy{Canary: 1}, ImageProgress{Hosts: 3, Verified: 1}, now) {
		t.Error("without a soak, a verified canary must admit the rest")
	}
	// No canary: everything goes.
	if !ImageAdmits(Strategy{Canary: 0, SoakSeconds: 300}, ImageProgress{Hosts: 3, Flying: 2}, now) {
		t.Error("with no canary there is nothing to wait for")
	}
}

// The case that motivated per-image pacing: an "Update All" rollout where the
// first host's images soak, and a host running a DIFFERENT image must not wait.
func TestUnrelatedImageDoesNotWaitForAnothersSoak(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	s := Strategy{Canary: 1, BatchSize: 5, SoakSeconds: 900}
	done := now.Add(-1 * time.Minute)
	soakingA := ImageProgress{Hosts: 3, Verified: 1, CanaryDoneAt: &done}
	untouchedB := ImageProgress{Hosts: 2}
	if HostAdmits(s, []ImageProgress{soakingA}, now) {
		t.Error("a host running A must wait for A's soak")
	}
	if !HostAdmits(s, []ImageProgress{untouchedB}, now) {
		t.Error("a host running only B must not wait for A's soak: it is B's canary")
	}
	if HostAdmits(s, []ImageProgress{soakingA, untouchedB}, now) {
		t.Error("a host running A and B waits: one of its images is still soaking")
	}
	if !HostAdmits(s, nil, now) {
		t.Error("a host running none of the images is admitted (it will be skipped)")
	}
}

func TestSoakDue(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	s := Strategy{Canary: 1, SoakSeconds: 300}
	early, late := now.Add(-time.Minute), now.Add(-10*time.Minute)
	if SoakDue(s, ImageProgress{CanaryDoneAt: &early}, now) {
		t.Error("not due before the soak runs out")
	}
	if !SoakDue(s, ImageProgress{CanaryDoneAt: &late}, now) {
		t.Error("due once the soak runs out")
	}
	if SoakDue(s, ImageProgress{CanaryDoneAt: &late, SoakChecked: true}, now) {
		t.Error("not due again once checked")
	}
	if SoakDue(Strategy{Canary: 1}, ImageProgress{CanaryDoneAt: &late}, now) {
		t.Error("never due without a soak")
	}
}
