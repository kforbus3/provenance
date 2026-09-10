package imaging

import (
	"testing"
	"time"
)

// The rollout engine, driven the way a fleet drives it: one report at a time.
//
// Every failure guarded here is silent in production, which is why this is a
// suite rather than a couple of smoke tests. A rollout that counts an install as
// a success ships a bricking update to the whole fleet while every machine
// quietly rolls back. One that never advances past the canary leaves an operator
// watching a bar that will not move. One that ignores its failure budget does
// the first thing on purpose. None of those raise, none log an error, and all of
// them look fine from outside until the fleet is already on the bad version.

func newRollout(strategy Strategy) *Rollout {
	return &Rollout{
		ID: "r-1", Bundle: "b.raucb", Version: "2.0",
		BundleURL: "http://example/bundles/b.raucb",
		State:     RolloutRunning, Strategy: strategy,
		Machines: map[string]*MachineProgress{},
	}
}

// report is one check-in: what the machine says it is running and doing.
func report(version, state string) Report {
	return Report{Version: version, Health: "ok", UpdateState: state}
}

func TestCanaryGoesFirstAndAlone(t *testing.T) {
	r := newRollout(Strategy{Canary: 1, BatchSize: 10, MaxFailures: 2})
	members := []string{"a", "b", "c"}
	offered := 0
	for _, id := range members {
		if act, _ := r.Evaluate(id, report("1.0", "idle"), members, false, time.Now()); act != nil {
			offered++
		}
	}
	if offered != 1 {
		t.Fatalf("offered the update to %d machines during the canary phase, want 1", offered)
	}
}

func TestAnInstallThatSaysItWorkedIsNotSuccess(t *testing.T) {
	// The one that matters most. The machine claims the install finished, but it
	// is still running the old version -- which is exactly what a bundle that
	// installs and then fails to boot looks like. Counting this as success is
	// how a bricking update reaches an entire fleet.
	r := newRollout(Strategy{Canary: 1, BatchSize: 10, MaxFailures: 2})
	members := []string{"a", "b", "c"}
	now := time.Now()
	r.Evaluate("a", report("1.0", "idle"), members, false, now) // takes the offer
	r.Evaluate("a", report("1.0", "installed"), members, false, now)

	if got := r.Machines["a"].State; got != StateRebooting {
		t.Fatalf("machine state is %q, want rebooting", got)
	}
	for _, id := range []string{"b", "c"} {
		if act, _ := r.Evaluate(id, report("1.0", "idle"), members, false, now); act != nil {
			t.Fatal("a second machine started on the strength of an install alone")
		}
	}
}

func TestSuccessIsComingBackOnTheNewVersion(t *testing.T) {
	r := newRollout(Strategy{Canary: 1, BatchSize: 10, MaxFailures: 2})
	members := []string{"a", "b"}
	now := time.Now()
	r.Evaluate("a", report("1.0", "idle"), members, false, now)
	r.Evaluate("a", report("2.0", "installed"), members, false, now)
	if got := r.Machines["a"].State; got != StateVerified {
		t.Fatalf("machine state is %q, want verified", got)
	}
}

func TestAMachineThatComesBackDegradedIsNotSuccess(t *testing.T) {
	// A machine that boots with its application dead has not been updated, it
	// has been broken, and a rollout must not march on believing otherwise.
	r := newRollout(Strategy{Canary: 1, BatchSize: 10, MaxFailures: 2})
	members := []string{"a", "b"}
	now := time.Now()
	r.Evaluate("a", report("1.0", "idle"), members, false, now)
	r.Evaluate("a", Report{Version: "2.0", Health: "degraded", UpdateState: "installed"},
		members, false, now)
	if r.Machines["a"].State == StateVerified {
		t.Fatal("a degraded machine on the target version was counted as verified")
	}
	r.Evaluate("a", report("2.0", "installed"), members, false, now)
	if r.Machines["a"].State != StateVerified {
		t.Fatal("it was not verified once it came up clean")
	}
}

func TestTheFailureBudgetHaltsTheRollout(t *testing.T) {
	r := newRollout(Strategy{Canary: 0, BatchSize: 10, MaxFailures: 2})
	members := []string{"a", "b", "c", "d"}
	now := time.Now()
	for _, id := range []string{"a", "b"} {
		r.Evaluate(id, report("1.0", "idle"), members, false, now)
		r.Evaluate(id, Report{UpdateState: "failed", UpdateError: "rauc exit 1"},
			members, false, now)
	}
	if r.State != RolloutHalted {
		t.Fatalf("rollout is %q after two failures, want halted", r.State)
	}
	if act, _ := r.Evaluate("c", report("1.0", "idle"), members, false, now); act != nil {
		t.Fatal("a halted rollout offered the update to another machine")
	}
}

func TestResumingForgivesTheFailuresThatStoppedIt(t *testing.T) {
	// Without this, resuming a rollout that halted on its budget re-halts on the
	// very next check-in -- the failures are still on the record and still over
	// the limit -- and `resume` becomes a button that returns success and does
	// nothing, which is worse than one that refuses.
	r := newRollout(Strategy{Canary: 0, BatchSize: 10, MaxFailures: 2})
	members := []string{"a", "b", "c"}
	now := time.Now()
	for _, id := range []string{"a", "b"} {
		r.Evaluate(id, report("1.0", "idle"), members, false, now)
		r.Evaluate(id, Report{UpdateState: "failed"}, members, false, now)
	}
	r.Resume()
	act, _ := r.Evaluate("c", report("1.0", "idle"), members, false, now)
	if act == nil {
		t.Fatal("the remaining machine was not offered the update after a resume")
	}
	if r.State != RolloutRunning {
		t.Fatalf("rollout re-halted immediately: %q", r.State)
	}
}

func TestTheSoakKeepsTheFleetBehindTheCanary(t *testing.T) {
	r := newRollout(Strategy{Canary: 1, BatchSize: 10, SoakSeconds: 3600, MaxFailures: 5})
	members := []string{"a", "b", "c"}
	now := time.Now()
	r.Evaluate("a", report("1.0", "idle"), members, false, now)
	r.Evaluate("a", report("2.0", "installed"), members, false, now)
	if r.CanaryDoneAt == nil {
		t.Fatal("the end of the canary phase was not stamped")
	}
	for _, id := range []string{"b", "c"} {
		if act, _ := r.Evaluate(id, report("1.0", "idle"), members, false, now); act != nil {
			t.Fatal("a machine started during the soak")
		}
	}
	// An update that bricks a machine ten minutes in is still a bricked machine.
	later := now.Add(2 * time.Hour)
	for _, id := range []string{"b", "c"} {
		if act, _ := r.Evaluate(id, report("1.0", "idle"), members, false, later); act == nil {
			t.Fatal("a machine was still held after the soak had elapsed")
		}
	}
}

func TestTheSoakIsACanaryGateNotADelayBetweenEveryBatch(t *testing.T) {
	// Timing the soak from whichever machine verified most recently re-arms it
	// as each batch lands, so every batch soaks too: five hundred machines in
	// tens with a fifteen-minute soak becomes twelve hours rather than the
	// "prove it on one, then go" the flag is documented and drawn as.
	//
	// batch_size 1 makes the batches strictly sequential, so a re-arming soak
	// would stop the third machine.
	r := newRollout(Strategy{Canary: 1, BatchSize: 1, SoakSeconds: 3600, MaxFailures: 9})
	members := []string{"a", "b", "c", "d"}
	now := time.Now()
	r.Evaluate("a", report("1.0", "idle"), members, false, now)
	r.Evaluate("a", report("2.0", "installed"), members, false, now)

	later := now.Add(2 * time.Hour) // the soak elapses once
	done := 1
	for _, id := range []string{"b", "c", "d"} {
		if act, _ := r.Evaluate(id, report("1.0", "idle"), members, false, later); act == nil {
			t.Fatalf("%s was held; the soak re-armed after a batch", id)
		}
		r.Evaluate(id, report("2.0", "installed"), members, false, later)
		done++
	}
	if done != 4 {
		t.Fatalf("only %d machines got through", done)
	}
}

func TestAHeldMachineIsSkippedWithoutHoldingUpTheRest(t *testing.T) {
	r := newRollout(Strategy{Canary: 0, BatchSize: 10, MaxFailures: 5})
	members := []string{"a", "b"}
	now := time.Now()
	if act, _ := r.Evaluate("a", report("1.0", "idle"), members, true, now); act != nil {
		t.Fatal("a held machine was offered an update")
	}
	if act, _ := r.Evaluate("b", report("1.0", "idle"), members, false, now); act == nil {
		t.Fatal("the rest of the group was held up by a held machine")
	}
}

func TestAMaintenanceWindowGatesWhenAMachineMayStart(t *testing.T) {
	r := newRollout(Strategy{Canary: 0, BatchSize: 5, MaxFailures: 5})
	members := []string{"a"}
	// A window that cannot contain the moment being tested, whenever it runs.
	r.Window = &Window{Start: "03:00", End: "03:01", Days: []int{}}
	noon := time.Date(2026, 9, 3, 12, 0, 0, 0, time.Local)
	if act, _ := r.Evaluate("a", report("1.0", "idle"), members, false, noon); act != nil {
		t.Fatal("a machine started outside the maintenance window")
	}
	r.Window = &Window{Start: "00:00", End: "23:59"}
	if act, _ := r.Evaluate("a", report("1.0", "idle"), members, false, noon); act == nil {
		t.Fatal("a machine was held inside the maintenance window")
	}
}

func TestAWindowThatWrapsPastMidnightStillCoversTheSmallHours(t *testing.T) {
	// "Sat 22:00-04:00" has to permit work at 01:00 on Sunday morning; a naive
	// start<=now<end comparison silently covers nothing at all.
	r := newRollout(Strategy{Canary: 0, BatchSize: 5, MaxFailures: 5})
	r.Window = &Window{Start: "22:00", End: "04:00"}
	oneAM := time.Date(2026, 9, 3, 1, 0, 0, 0, time.Local)
	if !r.inWindow(oneAM) {
		t.Fatal("01:00 is not inside a 22:00-04:00 window")
	}
	if r.inWindow(time.Date(2026, 9, 3, 12, 0, 0, 0, time.Local)) {
		t.Fatal("midday is inside a 22:00-04:00 window")
	}
}

func TestAnAbandonedOfferGoesBackInThePool(t *testing.T) {
	// A machine that took the offer and went silent -- powered off mid-download,
	// say. Without a timeout the single canary slot is occupied for ever and the
	// rollout never finishes, with nothing anywhere saying why.
	r := newRollout(Strategy{Canary: 1, BatchSize: 1, MaxFailures: 9})
	members := []string{"a", "b"}
	now := time.Now()
	r.Evaluate("a", report("1.0", "idle"), members, false, now)
	if act, _ := r.Evaluate("b", report("1.0", "idle"), members, false, now); act != nil {
		t.Fatal("two machines were started with a canary of one")
	}
	later := now.Add(OfferTimeout + time.Minute)
	if act, _ := r.Evaluate("b", report("1.0", "idle"), members, false, later); act == nil {
		t.Fatal("the slot was never freed after the offer timed out")
	}
}

func TestARolloutCompletesWhenEveryMachineIsDone(t *testing.T) {
	r := newRollout(Strategy{Canary: 0, BatchSize: 10, MaxFailures: 5})
	members := []string{"a", "b"}
	now := time.Now()
	for _, id := range members {
		r.Evaluate(id, report("1.0", "idle"), members, false, now)
		r.Evaluate(id, report("2.0", "installed"), members, false, now)
	}
	if r.State != RolloutCompleted {
		t.Fatalf("rollout is %q with every machine verified, want completed", r.State)
	}
}

func TestPresenceIsAboutSilenceNotFailure(t *testing.T) {
	now := time.Now()
	interval := 5 * time.Minute
	recent := now.Add(-time.Minute)
	oneMissed := now.Add(-7 * time.Minute)
	fourMissed := now.Add(-25 * time.Minute)
	aDayAgo := now.Add(-25 * time.Hour)

	for _, c := range []struct {
		name string
		at   *time.Time
		want string
	}{
		{"just now", &recent, "online"},
		{"one missed beat", &oneMissed, "online"},
		{"four missed beats", &fourMissed, "stale"},
		{"a day of silence", &aDayAgo, "offline"},
		// The distinction that stops the page filling with false alarms: a
		// machine that never ran an agent has not gone quiet, it was never
		// speaking.
		{"never heard from", nil, "unknown"},
	} {
		if got := Presence(c.at, interval, now); got != c.want {
			t.Errorf("%s: presence %q, want %q", c.name, got, c.want)
		}
	}
}

func TestAnAmbiguousHostnameMatchesNothing(t *testing.T) {
	// Two machines answering to one name make the name useless as an
	// identifier. Picking one at random sends half the updates to the wrong
	// machine, silently, which is worse than admitting the name is no good.
	unique := MatchByHostname([]string{"web01", "web01", "db01", "app01.example.com"})
	if unique["web01"] {
		t.Fatal("a duplicated hostname was treated as a match")
	}
	if !unique["db01"] || !unique["app01"] {
		t.Fatalf("unambiguous names were not matched: %+v", unique)
	}
}

// A machine's memory of an OLD rollout must not decide a new one.
//
// The agent remembers what it is in the middle of across reboots, so it keeps
// reporting update_state=failed long after the rollout that offered the bundle
// has finished. It sends the rollout id alongside — and nothing read it, so the
// stale failure was folded into whatever rollout was evaluating the machine
// next.
//
// The symptom is unmistakable once you know it: a brand-new rollout, with a
// brand-new bundle, reporting "completed · failed: 1" within seconds, carrying
// the previous attempt's error message, and attempts=0 — because the machine
// was never actually offered anything. Fixing the underlying problem and
// starting a fresh rollout could not clear it; every new rollout inherited the
// same corpse.
func TestAnOldFailureDoesNotFailANewRollout(t *testing.T) {
	r := newRollout(Strategy{Canary: 1, BatchSize: 10, MaxFailures: 2})
	members := []string{"a"}

	stale := Report{
		Version: "1.0", Health: "ok", UpdateState: "failed",
		UpdateError: "rauc: error while loading shared libraries: libjson-glib-1.0.so.0",
		Rollout:     "r-0", // the rollout before this one
	}

	act, _ := r.Evaluate("a", stale, members, false, time.Now())
	m := r.progress("a")

	if m.State == StateFailed {
		t.Fatalf("a new rollout inherited a failure from rollout %q: state=%s error=%q",
			stale.Rollout, m.State, m.Error)
	}
	if act == nil {
		t.Fatal("the machine was not offered the bundle; a stale report should not " +
			"stop a rollout from trying")
	}
	if m.Attempts != 1 {
		t.Errorf("attempts = %d, want 1 — the machine was offered the bundle", m.Attempts)
	}
}

// The same report, naming THIS rollout, is exactly what it looks like.
func TestAFailureForThisRolloutStillCounts(t *testing.T) {
	r := newRollout(Strategy{Canary: 1, BatchSize: 10, MaxFailures: 2})
	members := []string{"a"}
	now := time.Now()

	r.Evaluate("a", report("1.0", "idle"), members, false, now) // offered
	r.Evaluate("a", Report{
		Version: "1.0", Health: "ok", UpdateState: "failed",
		UpdateError: "install failed", Rollout: r.ID,
	}, members, false, now)

	if got := r.progress("a").State; got != StateFailed {
		t.Errorf("state = %s, want failed — this rollout's own failure must count", got)
	}
}

// An agent old enough not to send the id keeps working, with the behaviour it
// has always had. Accepting these is a deliberate trade: those machines are no
// worse off than before, and refusing them would break every fleet mid-upgrade.
func TestAReportWithNoRolloutIdIsStillAccepted(t *testing.T) {
	r := newRollout(Strategy{Canary: 1, BatchSize: 10, MaxFailures: 2})
	members := []string{"a"}
	now := time.Now()

	r.Evaluate("a", report("1.0", "idle"), members, false, now)
	r.Evaluate("a", Report{Version: "1.0", Health: "ok", UpdateState: "failed"}, members, false, now)

	if got := r.progress("a").State; got != StateFailed {
		t.Errorf("state = %s, want failed — an agent that sends no rollout id must "+
			"still be able to report one", got)
	}
}
