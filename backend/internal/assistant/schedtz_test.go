package assistant

import (
	"testing"
	"time"

	"github.com/fleet-terminal/backend/internal/models"
)

// TestRecurrenceSummary_Timezone verifies the recurrence string carries the display
// zone for time-of-day schedules (so the model doesn't assume UTC) and omits it for
// interval schedules (which have no wall-clock time).
func TestRecurrenceSummary_Timezone(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	daily := recurrenceSummary(models.Recurrence{Type: "daily", TimeOfDay: "03:00"}, ny)
	// July → EDT, but accept either DST abbreviation to stay date-agnostic.
	if daily != "daily at 03:00 EDT" && daily != "daily at 03:00 EST" {
		t.Errorf("daily recurrence missing NY zone label: %q", daily)
	}
	interval := recurrenceSummary(models.Recurrence{Type: "interval", EveryMinutes: 30}, ny)
	if interval != "every 30m" {
		t.Errorf("interval recurrence should have no zone: %q", interval)
	}
}

// TestInLoc shifts a timestamp into the display zone without changing the instant,
// so the marshaled value carries the zone's offset rather than UTC's Z.
func TestInLoc(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	// 07:00 UTC in July is 03:00 EDT.
	utc := time.Date(2026, 7, 23, 7, 0, 0, 0, time.UTC)
	got := inLoc(&utc, ny)
	if got == nil {
		t.Fatal("inLoc returned nil for a non-nil time")
	}
	if !got.Equal(utc) {
		t.Errorf("instant changed: %v != %v", got, utc)
	}
	if h := got.Hour(); h != 3 {
		t.Errorf("expected 03:00 wall-clock in NY, got %02d:00", h)
	}
	if inLoc(nil, ny) != nil {
		t.Error("inLoc(nil) should be nil")
	}
}
