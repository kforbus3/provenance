package imaging

import (
	"fmt"
	"time"
)

// The rollout engine, brought across from Flipside.
//
// An operator says "put group prod on bundle 1.4.0, one machine first, then ten
// at a time, and stop if two fail". That intent is recorded; nothing is sent
// anywhere by it. A machine's check-in, or an operator's system reporting what
// it observed on a machine, is what moves a rollout forward.
//
// Deliberately pure. Every function here takes a rollout, a report and a clock
// and returns a decision; nothing reads a database, a socket or the wall clock.
// That is what makes the rules testable at all -- canary, soak, batching and
// the failure budget are the parts that can be silently wrong, and each of them
// is wrong in a way that only shows up as "the fleet is on the bad version".
//
// The state a machine moves through:
//
//	pending     in the rollout, not yet told to do anything
//	offered     told; has not yet said it started
//	installing  reported downloading or installing
//	rebooting   reported the install finished; awaiting the new boot
//	verified    came back on the target version and passed its health check
//	failed      reported a failure, or never progressed
//	skipped     held back by an operator
//
// `verified` is not "it said the install worked". A bundle that installs
// perfectly and then fails to boot is the exact failure the A/B layout exists to
// survive, and a rollout that counted the install would march that bundle across
// the whole fleet while every machine quietly rolled back. Success means the
// machine came back, on the new version, healthy.

const (
	StatePending    = "pending"
	StateOffered    = "offered"
	StateInstalling = "installing"
	StateRebooting  = "rebooting"
	StateVerified   = "verified"
	StateFailed     = "failed"
	StateSkipped    = "skipped"
)

const (
	RolloutRunning   = "running"
	RolloutPaused    = "paused"
	RolloutHalted    = "halted"
	RolloutCompleted = "completed"
	RolloutCancelled = "cancelled"
)

const (
	// How long a machine may sit offered or installing before the rollout gives
	// up waiting and offers the slot to somebody else. Generous: a large bundle
	// over a slow link, on a machine that also has to reboot, is not a failure.
	OfferTimeout = time.Hour
	// How many times one machine may be re-offered before it counts as failed.
	// A machine that takes the offer and vanishes three times is not going to
	// work.
	MaxAttempts = 3
)

func terminal(state string) bool {
	return state == StateVerified || state == StateFailed || state == StateSkipped
}

func inFlight(state string) bool {
	return state == StateOffered || state == StateInstalling || state == StateRebooting
}

// MachineProgress is one machine's place in one rollout.
type MachineProgress struct {
	State     string
	Error     string
	Attempts  int
	ChangedAt time.Time
}

// Strategy is how fast a rollout is allowed to go.
type Strategy struct {
	Canary      int
	BatchSize   int
	SoakSeconds int
	MaxFailures int
}

// Window is when a rollout may *start* machines, in server-local time.
//
// Server-local on purpose. The alternative -- each machine deciding against its
// own clock -- means a maintenance window means different things on different
// machines, and the machine whose timezone is wrong is exactly the one nobody
// notices until it reboots mid-shift.
type Window struct {
	Start string // "22:00"
	End   string // "04:00"
	Days  []int  // time.Weekday values; empty means every day
}

// Rollout is the engine's view of one. The store fills it in and writes back
// whatever the engine changed.
type Rollout struct {
	ID           string
	Bundle       string
	Version      string
	BundleURL    string
	State        string
	HaltReason   string
	Strategy     Strategy
	Window       *Window
	CanaryDoneAt *time.Time
	// Failures counted before the last resume. Resuming means "I have looked at
	// those; carry on with the rest", so the budget starts again from here --
	// without it a rollout that halted on its budget re-halts on the very next
	// heartbeat, and `resume` becomes a button that returns success and does
	// nothing, which is worse than one that refuses.
	FailureBaseline int
	Machines        map[string]*MachineProgress
}

// Report is what a machine said about itself, or what something said about the
// machine having looked at it.
type Report struct {
	Version     string
	Health      string
	UpdateState string // downloading | installing | installed | failed | idle
	UpdateError string
	// Rollout is the rollout the update state belongs to, as the machine
	// remembers it. The agent has always sent this and nothing read it.
	//
	// Its absence was a real bug: a machine remembers what it is in the middle
	// of across reboots, so it keeps reporting update_state=failed long after
	// the rollout that offered the bundle has gone. Without the id, that report
	// was folded into whatever rollout happened to be evaluating the machine
	// next -- so a machine that failed once failed every rollout afterwards,
	// instantly, with attempts=0 because it was never actually offered
	// anything. Fixing the cause and starting a new rollout could not clear it.
	//
	// Empty for an agent old enough not to send it, which is accepted rather
	// than ignored: those machines have the old behaviour and nothing worse.
	Rollout string
}

// Action is what to tell a machine. Nil means nothing to do.
type Action struct {
	Type      string // "update"
	RolloutID string
	BundleURL string
	Version   string
}

func (r *Rollout) progress(id string) *MachineProgress {
	if r.Machines == nil {
		r.Machines = map[string]*MachineProgress{}
	}
	m, ok := r.Machines[id]
	if !ok {
		m = &MachineProgress{State: StatePending}
		r.Machines[id] = m
	}
	return m
}

// Failures counts machines this rollout has given up on since it was last
// resumed.
func (r *Rollout) Failures() int {
	n := 0
	for _, m := range r.Machines {
		if m.State == StateFailed {
			n++
		}
	}
	return n - r.FailureBaseline
}

// Complete reports whether every machine in the target has finished, one way or
// another.
func (r *Rollout) Complete(members []string) bool {
	if len(members) == 0 {
		return false
	}
	for _, id := range members {
		m, ok := r.Machines[id]
		if !ok || !terminal(m.State) {
			return false
		}
	}
	return true
}

// applyReport folds what a machine said into its place in the rollout.
func (r *Rollout) applyReport(id string, rep Report, now time.Time) bool {
	m := r.progress(id)
	before := *m

	// Success, defined as the machine coming back rather than as the install
	// returning zero. Checked first, because a machine that reports "installed"
	// *and* the target version has already done both things.
	if inFlight(m.State) && rep.Version != "" && rep.Version == r.Version {
		if rep.Health == "" || rep.Health == "ok" {
			m.State = StateVerified
			m.ChangedAt = now
			m.Error = ""
			return true
		}
	}

	// Only what this machine says about THIS rollout. A report naming a
	// different one is the machine's memory of an earlier update, and applying
	// it here would let an old failure decide a new rollout's outcome.
	if rep.Rollout != "" && rep.Rollout != r.ID {
		return *m != before
	}

	switch rep.UpdateState {
	case "downloading", "installing":
		m.State = StateInstalling
		m.ChangedAt = now
	case "installed":
		m.State = StateRebooting
		m.ChangedAt = now
	case "failed":
		m.State = StateFailed
		m.ChangedAt = now
		m.Error = rep.UpdateError
		if m.Error == "" {
			m.Error = "the machine reported a failure"
		}
	}
	return *m != before
}

// sweepTimeouts returns abandoned offers to the pool so a rollout cannot wedge.
//
// Done when a machine asks rather than on a timer, for the same reason the rest
// of this has no scheduler: the only moment the answer matters is when somebody
// is asking, and at that moment it is cheap to work out.
func (r *Rollout) sweepTimeouts(now time.Time) bool {
	changed := false
	for _, m := range r.Machines {
		if !inFlight(m.State) || now.Sub(m.ChangedAt) < OfferTimeout {
			continue
		}
		if m.Attempts >= MaxAttempts {
			m.State = StateFailed
			m.Error = fmt.Sprintf("no progress after %d attempts; the machine took "+
				"the update and never reported back", m.Attempts)
		} else {
			m.State = StatePending
		}
		m.ChangedAt = now
		changed = true
	}
	return changed
}

// capacity is how many more machines may start right now. Zero means "not yet".
func (r *Rollout) capacity(now time.Time) int {
	var flying, verified int
	for _, m := range r.Machines {
		if inFlight(m.State) {
			flying++
		}
		if m.State == StateVerified {
			verified++
		}
	}
	canary := r.Strategy.Canary
	if canary < 0 {
		canary = 0
	}

	if verified < canary {
		// Still proving the canaries. Never more than `canary` at once, and a
		// failed canary means the batch phase is never reached at all.
		return max(0, canary-flying)
	}

	if canary > 0 && r.Strategy.SoakSeconds > 0 {
		// The canaries have to have been up for a while before the rest of the
		// fleet follows. An update that bricks a machine ten minutes in is
		// still a bricked machine, and without this the whole fleet would
		// already have it.
		if r.CanaryDoneAt == nil {
			return 0
		}
		if now.Sub(*r.CanaryDoneAt) < time.Duration(r.Strategy.SoakSeconds)*time.Second {
			return 0
		}
	}

	batch := r.Strategy.BatchSize
	if batch < 1 {
		batch = 1
	}
	return max(0, batch-flying)
}

// inWindow reports whether the rollout may start machines at this moment.
func (r *Rollout) inWindow(now time.Time) bool {
	w := r.Window
	if w == nil || w.Start == "" || w.End == "" {
		return true
	}
	start, err1 := parseHM(w.Start)
	end, err2 := parseHM(w.End)
	if err1 != nil || err2 != nil {
		// An unparseable window is not a reason to stop a rollout forever;
		// it is a reason for the window not to apply.
		return true
	}
	minutes := now.Hour()*60 + now.Minute()
	onDay := func(d time.Weekday) bool {
		if len(w.Days) == 0 {
			return true
		}
		for _, allowed := range w.Days {
			if time.Weekday(allowed) == d {
				return true
			}
		}
		return false
	}
	if start <= end {
		return onDay(now.Weekday()) && minutes >= start && minutes < end
	}
	// A window that wraps past midnight belongs to the day it *started* on, so
	// "Sat 22:00-04:00" permits work at 23:00 on Saturday and at 01:00 on Sunday
	// morning -- and at neither noon.
	//
	// The second half needs the `minutes < end` test as much as the first needs
	// `minutes >= start`. Without it every moment before the start hour falls
	// through to "was yesterday an allowed day", which for the common case of no
	// day restriction is always true -- so a 22:00-04:00 window silently permits
	// updates at any hour, which is the exact opposite of what it was set for
	// and is invisible until a machine reboots in the middle of the day.
	if minutes >= start {
		return onDay(now.Weekday())
	}
	return minutes < end && onDay((now.Weekday()+6)%7)
}

func parseHM(s string) (int, error) {
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
		return 0, err
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("out of range")
	}
	return h*60 + m, nil
}

// Evaluate folds one report into the rollout and says what the machine should do
// next. It returns whether anything about the rollout changed, so the caller
// only writes when there is something to write.
//
// held is the machine's own hold flag: it stays in its groups and keeps
// reporting, but is never offered an update, and the rest of the group carries
// on without waiting for it.
func (r *Rollout) Evaluate(machineID string, rep Report, members []string, held bool, now time.Time) (*Action, bool) {
	changed := r.applyReport(machineID, rep, now)

	// The moment the canary phase finished, stamped once. See CanaryDoneAt.
	if r.Strategy.Canary > 0 && r.CanaryDoneAt == nil {
		verified := 0
		for _, m := range r.Machines {
			if m.State == StateVerified {
				verified++
			}
		}
		if verified >= r.Strategy.Canary {
			at := now
			r.CanaryDoneAt = &at
			changed = true
		}
	}

	var action *Action
	m := r.progress(machineID)
	if r.State == RolloutRunning && m.State == StatePending && !held {
		if r.sweepTimeouts(now) {
			changed = true
		}
		if r.inWindow(now) && r.capacity(now) > 0 {
			m.State = StateOffered
			m.ChangedAt = now
			m.Attempts++
			m.Error = ""
			changed = true
			action = &Action{
				Type: "update", RolloutID: r.ID,
				BundleURL: r.BundleURL, Version: r.Version,
			}
		}
	}

	if budget := r.Strategy.MaxFailures; budget > 0 && r.State == RolloutRunning {
		if failed := r.Failures(); failed >= budget {
			r.State = RolloutHalted
			r.HaltReason = fmt.Sprintf("%d machines failed; the rollout stopped on its own.", failed)
			changed = true
			action = nil // nothing further goes out under a halted rollout
		}
	}

	if r.State == RolloutRunning && r.Complete(members) {
		r.State = RolloutCompleted
		changed = true
	}
	return action, changed
}

// Resume restarts a halted or paused rollout, forgiving the failures that
// stopped it. The machines that failed stay failed; the budget counts from here.
func (r *Rollout) Resume() {
	r.FailureBaseline = 0
	for _, m := range r.Machines {
		if m.State == StateFailed {
			r.FailureBaseline++
		}
	}
	r.State = RolloutRunning
	r.HaltReason = ""
}

// Counts is the per-state tally an operator actually looks at.
func (r *Rollout) Counts(members []string) map[string]int {
	out := map[string]int{}
	for _, id := range members {
		state := StatePending
		if m, ok := r.Machines[id]; ok {
			state = m.State
		}
		out[state]++
	}
	return out
}
