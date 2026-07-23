package assistant

import (
	"testing"

	"github.com/fleet-terminal/backend/internal/models"
)

// TestDiskFreeSummary reproduces the nas case the user flagged: the host card
// shows / at 64% used while the headline "disk free %" is 31% — the two use
// different denominators (used/size vs df-Available/size), so the summary must
// name / as the tightest mount and expose both numbers to explain the gap.
func TestDiskFreeSummary(t *testing.T) {
	m := &models.HostMetrics{Disk: []models.DiskFS{
		{Mount: "/", SizeBytes: 13_900_000_000, UsedBytes: 8_870_000_000, AvailBytes: 4_330_000_000, UsePct: 64},
		{Mount: "/mnt/p03/ROMs", SizeBytes: 32_000_000_000_000, UsedBytes: 12_000_000_000_000, AvailBytes: 20_000_000_000_000, UsePct: 37},
	}}
	ds := diskFreeSummary(m)
	if ds == nil {
		t.Fatal("expected a disk summary")
	}
	if got := ds["tightestMount"]; got != "/" {
		t.Errorf("tightestMount = %v, want /", got)
	}
	free, _ := ds["diskFreePct"].(float64)
	if free < 30.5 || free > 31.5 {
		t.Errorf("diskFreePct = %v, want ~31 (avail/size on /)", free)
	}
}

func TestDiskFreeSummaryEmpty(t *testing.T) {
	if diskFreeSummary(nil) != nil {
		t.Error("nil metrics should yield no summary")
	}
	if diskFreeSummary(&models.HostMetrics{}) != nil {
		t.Error("no filesystems should yield no summary")
	}
}

func TestHoursFromText(t *testing.T) {
	cases := map[string]int{
		"did any host go offline today?":     24,
		"was nas down overnight":             24,
		"any outages this week?":             168,
		"what went offline yesterday":        48,
		"downtime over the past month":       720,
		"has anything been offline recently": 168, // default
	}
	for q, want := range cases {
		if got := hoursFromText(q); got != want {
			t.Errorf("hoursFromText(%q) = %d, want %d", q, got, want)
		}
	}
}
