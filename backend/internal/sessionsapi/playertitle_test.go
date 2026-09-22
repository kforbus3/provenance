package sessionsapi

import (
	"strings"
	"testing"
	"time"
)

// The bug: the player page's <title> formatted the session's start time server-side with
// no zone. The shipped backend image runs TZ=UTC, while an operator's configured display
// zone was America/New_York — so the tab title read four hours away from the same
// session's row in the Sessions list, which the browser renders in the viewer's zone.

func TestPlayerTitleRendersInTheDisplayZone(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	// 15:07 UTC is 11:07 EDT — the exact shape of the reported mismatch.
	started := time.Date(2026, 9, 22, 15, 7, 44, 0, time.UTC)

	got := playerTitle("alice", "web-01", started, ny)

	if !strings.Contains(got, "11:07:44") {
		t.Errorf("title did not use the display zone: %q (want the 11:07:44 EDT rendering "+
			"of 15:07:44 UTC)", got)
	}
	if strings.Contains(got, "15:07:44") {
		t.Errorf("title still shows the server's UTC wall clock: %q", got)
	}
}

// A time with no zone printed is a guess, because the fallbacks differ: with no timezone
// configured the UI uses the browser's zone and DisplayLocation the server's. So the
// label is not decoration — it is what makes the title verifiable.
func TestPlayerTitleNamesItsZone(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	got := playerTitle("alice", "web-01", time.Date(2026, 9, 22, 15, 7, 44, 0, time.UTC), ny)
	if !strings.Contains(got, "EDT") {
		t.Errorf("title does not name the zone it rendered in: %q", got)
	}

	// And in winter it must say EST, not a hardcoded abbreviation.
	winter := playerTitle("alice", "web-01", time.Date(2026, 1, 15, 15, 7, 44, 0, time.UTC), ny)
	if !strings.Contains(winter, "EST") {
		t.Errorf("title does not track the zone's offset across DST: %q", winter)
	}
}

func TestPlayerTitleSurvivesANilZone(t *testing.T) {
	got := playerTitle("alice", "web-01", time.Date(2026, 9, 22, 15, 7, 44, 0, time.UTC), nil)
	if !strings.Contains(got, "alice@web-01") || !strings.Contains(got, "UTC") {
		t.Errorf("nil zone should fall back to a labelled UTC rendering, got %q", got)
	}
}
