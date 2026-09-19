package digest

import (
	"testing"
	"time"
)

func at(y int, mo time.Month, d, h int) time.Time {
	return time.Date(y, mo, d, h, 0, 0, 0, time.UTC)
}

func TestDueDaily(t *testing.T) {
	p := Policy{Enabled: true, Frequency: "daily", Hour: 8}
	if !p.due(at(2026, 7, 17, 8)) {
		t.Fatal("expected due at the configured hour")
	}
	if p.due(at(2026, 7, 17, 9)) {
		t.Fatal("should not be due outside the configured hour")
	}
	// Already sent earlier today → not due again.
	p.LastSent = at(2026, 7, 17, 8).Unix()
	if p.due(at(2026, 7, 17, 8)) {
		t.Fatal("should not re-send within the same day")
	}
	// Next day, same hour → due again.
	if !p.due(at(2026, 7, 18, 8)) {
		t.Fatal("expected due the next day")
	}
}

func TestDueWeekly(t *testing.T) {
	// July 20 2026 is a Monday (weekday 1).
	p := Policy{Enabled: true, Frequency: "weekly", Hour: 9, Weekday: 1}
	if !p.due(at(2026, 7, 20, 9)) {
		t.Fatal("expected due on the configured weekday+hour")
	}
	if p.due(at(2026, 7, 21, 9)) {
		t.Fatal("should not be due on a different weekday")
	}
}

func TestDueDisabled(t *testing.T) {
	p := Policy{Enabled: false, Frequency: "daily", Hour: 8}
	if p.due(at(2026, 7, 17, 8)) {
		t.Fatal("disabled digest must never be due")
	}
}

func TestNormalizeClampsBadValues(t *testing.T) {
	got := normalize(Policy{Frequency: "hourly", Hour: 99, Weekday: 12})
	if got.Frequency != "daily" || got.Hour != 8 || got.Weekday != 1 {
		t.Fatalf("normalize did not clamp: %+v", got)
	}
}

// The digest ships enabled: an insight engine nobody reads does nothing, and a
// fresh install should start summarizing the fleet without the operator having to
// discover the feature first.
func TestDefaultPolicyIsEnabledDaily(t *testing.T) {
	p := policyFromRaw(nil)
	if !p.Enabled {
		t.Fatal("digest should be enabled by default")
	}
	if p.Frequency != "daily" || p.Hour != 8 {
		t.Fatalf("default schedule = %s at %d, want daily at 8", p.Frequency, p.Hour)
	}
	// And the default actually fires, rather than being enabled but never due.
	if !p.due(time.Date(2026, 9, 19, 8, 5, 0, 0, time.Local)) {
		t.Fatal("default policy is enabled but never due")
	}
}

// Changing the default must not resurrect the digest for an operator who turned it
// off: a stored document wins over the default, field by field.
func TestStoredPolicyOverridesTheDefault(t *testing.T) {
	p := policyFromRaw([]byte(`{"enabled":false,"frequency":"weekly","hour":20,"weekday":5}`))
	if p.Enabled {
		t.Fatal("stored enabled:false was overridden by the new default")
	}
	if p.Frequency != "weekly" || p.Hour != 20 || p.Weekday != 5 {
		t.Fatalf("stored schedule not preserved: %+v", p)
	}
}
