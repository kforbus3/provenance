// Package pacing holds the rules that decide how fast a staged rollout is
// allowed to go.
//
// Extracted from the image rollout engine because container updates need the
// same rules and a second copy would drift. These are exactly the rules that can
// be silently wrong: each of canary, soak, batching, the maintenance window and
// the failure budget is wrong in a way whose only symptom is "the whole fleet
// took the bad version at once", which is discovered after the fact or not at
// all. One implementation, one set of tests.
//
// Deliberately pure. Every function takes its inputs and a clock and returns a
// decision; nothing here reads a database, a socket or the wall clock.
package pacing

import (
	"fmt"
	"time"
)

// Strategy is how fast a rollout is allowed to go.
type Strategy struct {
	Canary      int
	BatchSize   int
	SoakSeconds int
	MaxFailures int
}

// Window is when a rollout may *start* work, in server-local time.
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

// Capacity is how many more targets may start right now. Zero means "not yet".
//
// flying is how many are mid-update; verified is how many have finished
// successfully. canaryDoneAt is when the canary phase completed, or nil if it
// has not.
func Capacity(s Strategy, flying, verified int, canaryDoneAt *time.Time, now time.Time) int {
	canary := s.Canary
	if canary < 0 {
		canary = 0
	}

	if verified < canary {
		// Still proving the canaries. `canary` is how many machines prove the
		// update in total, so the ones that have already verified count against
		// it: subtracting only the in-flight ones lets a canary of 2 start two
		// more the moment the first verifies, and three machines take an
		// unproven update where the operator asked for two.
		//
		// A failed canary means the batch phase is never reached at all, because
		// verified never reaches `canary`.
		return max(0, canary-verified-flying)
	}

	if canary > 0 && s.SoakSeconds > 0 {
		// The canaries have to have been up for a while before the rest of the
		// fleet follows. An update that breaks something ten minutes in is still
		// broken, and without this the whole fleet would already have it.
		if canaryDoneAt == nil {
			return 0
		}
		if now.Sub(*canaryDoneAt) < time.Duration(s.SoakSeconds)*time.Second {
			return 0
		}
	}

	batch := s.BatchSize
	if batch < 1 {
		batch = 1
	}
	return max(0, batch-flying)
}

// InWindow reports whether a rollout may start work at this moment.
func InWindow(w *Window, now time.Time) bool {
	if w == nil || w.Start == "" || w.End == "" {
		return true
	}
	start, err1 := ParseHM(w.Start)
	end, err2 := ParseHM(w.End)
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

// ParseHM parses "HH:MM" into minutes since midnight.
func ParseHM(s string) (int, error) {
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
		return 0, err
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("out of range")
	}
	return h*60 + m, nil
}

// BudgetExceeded reports whether a rollout has spent its failure budget.
//
// A budget of zero means unlimited, which is why this is a function and not a
// comparison written out at each call site: reading `failures > s.MaxFailures`
// as the whole rule silently makes a budget of zero halt on the first failure,
// turning "no limit" into "no tolerance".
func BudgetExceeded(s Strategy, failures int) bool {
	return s.MaxFailures > 0 && failures >= s.MaxFailures
}

// ImageProgress is where one image stands within a rollout that covers several.
//
// Canary and soak are per IMAGE, not per rollout. A rollout covering every
// available update used to prove the first host's images and then hold back every
// other host for the soak -- including hosts running images the canary never
// touched, which then went out unproven anyway once the soak expired. The pause
// protected nothing it delayed.
type ImageProgress struct {
	Hosts    int // rollout hosts that run this image
	Verified int // of those, how many have finished
	Flying   int // and how many are mid-update
	// When this image's canaries had all verified; nil until then.
	CanaryDoneAt *time.Time
	// Whether the canaries were re-checked, and passed, once the soak ran out.
	SoakChecked bool
}

// ImageCanaries is how many of an image's hosts prove it before the rest follow.
// An image running on fewer hosts than the canary count has no "rest": every one
// of its hosts is a canary, and nothing waits on a soak.
func ImageCanaries(s Strategy, p ImageProgress) int {
	c := s.Canary
	if c < 0 {
		c = 0
	}
	if c > p.Hosts {
		c = p.Hosts
	}
	return c
}

// SoakDue reports whether an image's soak has run out and its canaries are due to
// be re-checked.
func SoakDue(s Strategy, p ImageProgress, now time.Time) bool {
	if s.SoakSeconds <= 0 || p.CanaryDoneAt == nil || p.SoakChecked {
		return false
	}
	return now.Sub(*p.CanaryDoneAt) >= time.Duration(s.SoakSeconds)*time.Second
}

// ImageAdmits reports whether one more host running this image may start now.
//
// Yes while the image still has a free canary slot. Then no until every canary
// has verified -- and, when there is a soak, until it has run out and the
// canaries passed their re-check. After that, yes.
func ImageAdmits(s Strategy, p ImageProgress, now time.Time) bool {
	c := ImageCanaries(s, p)
	if c == 0 {
		return true
	}
	if p.Verified+p.Flying < c {
		return true // a canary slot is free
	}
	if p.Verified < c {
		return false // the canaries are still in flight (or one failed)
	}
	if s.SoakSeconds > 0 {
		if p.CanaryDoneAt == nil || now.Sub(*p.CanaryDoneAt) < time.Duration(s.SoakSeconds)*time.Second {
			return false
		}
		if !p.SoakChecked {
			return false
		}
	}
	return true
}

// HostAdmits reports whether a host may start: every image it would receive must
// admit it. A host that runs none of the rollout's images (it will be skipped)
// is admitted.
func HostAdmits(s Strategy, images []ImageProgress, now time.Time) bool {
	for _, p := range images {
		if !ImageAdmits(s, p, now) {
			return false
		}
	}
	return true
}
