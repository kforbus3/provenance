package reportsched

import (
	"testing"
	"time"
)

func at(y int, mo time.Month, d, h int) time.Time {
	return time.Date(y, mo, d, h, 0, 0, 0, time.UTC)
}

func TestDueMonthly(t *testing.T) {
	p := Policy{Enabled: true, Reports: []string{"access"}, Frequency: "monthly", DayOfMonth: 1, Hour: 6}
	if !p.due(at(2026, 8, 1, 6)) {
		t.Fatal("expected due on day-of-month at the configured hour")
	}
	if p.due(at(2026, 8, 2, 6)) {
		t.Fatal("should not be due on a different day of month")
	}
	if p.due(at(2026, 8, 1, 7)) {
		t.Fatal("should not be due at a different hour")
	}
	p.LastSent = at(2026, 8, 1, 6).Unix()
	if p.due(at(2026, 8, 1, 6)) {
		t.Fatal("should not re-send the same day")
	}
}

func TestDueWeekly(t *testing.T) {
	// 2026-08-03 is a Monday.
	p := Policy{Enabled: true, Reports: []string{"audit"}, Frequency: "weekly", Weekday: 1, Hour: 6}
	if !p.due(at(2026, 8, 3, 6)) {
		t.Fatal("expected due on configured weekday")
	}
	if p.due(at(2026, 8, 4, 6)) {
		t.Fatal("should not be due on a different weekday")
	}
}

func TestNotDueWhenEmptyOrDisabled(t *testing.T) {
	base := Policy{Enabled: true, Reports: []string{"access"}, Frequency: "monthly", DayOfMonth: 1, Hour: 6}
	off := base
	off.Enabled = false
	if off.due(at(2026, 8, 1, 6)) {
		t.Fatal("disabled must never be due")
	}
	empty := base
	empty.Reports = nil
	if empty.due(at(2026, 8, 1, 6)) {
		t.Fatal("no reports selected must never be due")
	}
}

func TestNormalizeDropsUnknownReportsAndClamps(t *testing.T) {
	got := normalize(Policy{Frequency: "daily", Hour: 40, DayOfMonth: 99, LookbackDays: 0,
		Reports: []string{"access", "bogus", "scans"}})
	if got.Frequency != "monthly" || got.Hour != 6 || got.DayOfMonth != 1 || got.LookbackDays != 31 {
		t.Fatalf("clamp failed: %+v", got)
	}
	if len(got.Reports) != 2 || got.Reports[0] != "access" || got.Reports[1] != "scans" {
		t.Fatalf("unknown report not dropped: %+v", got.Reports)
	}
}
