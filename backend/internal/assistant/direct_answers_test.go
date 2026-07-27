package assistant

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

func f64(v float64) *float64 { return &v }

func TestDiskFreeDirectAnswer(t *testing.T) {
	rows := []models.AssistantHostRow{
		{Hostname: "nas", MinDiskFreePct: f64(29.1)},
		{Hostname: "docker", MinDiskFreePct: f64(40.2)},
		{Hostname: "coder", MinDiskFreePct: f64(57.9)},
	}
	args, _ := json.Marshal(queryHostsArgs{DiskFreePctMax: f64(80)})
	got := diskFreeDirectAnswer("which hosts have less than 80% disk free", args, rows)
	// Must include the COUNT and EVERY host (sorted by %), never truncate.
	for _, want := range []string{"3 hosts", "less than 80% disk free", "nas (29.1%)", "docker (40.2%)", "coder (57.9%)"} {
		if !contains(got, want) {
			t.Errorf("disk answer missing %q: %s", want, got)
		}
	}
	// Empty -> clear "no hosts".
	if e := diskFreeDirectAnswer("less than 5% disk free", args, nil); e != "No hosts have less than 80% disk free." {
		t.Errorf("empty disk answer wrong: %q", e)
	}
	// Non-disk query -> defer (empty).
	na, _ := json.Marshal(queryHostsArgs{Status: "offline"})
	if d := diskFreeDirectAnswer("which hosts are offline", na, rows); d != "" {
		t.Errorf("non-disk query should defer, got %q", d)
	}
}

func TestAuditChangesDirectAnswer(t *testing.T) {
	payload := map[string]any{
		"changesByAction": map[string]int{"auth.login": 14, "system.upgrade_apply": 9, "settings.update": 2},
		"routineByAction": map[string]int{"assistant.query": 100, "certificate.issue": 20},
	}
	got := auditChangesDirectAnswer("what changed in the audit log today", payload)
	for _, want := range []string{"25 changes today", "14 auth.login", "9 system.upgrade_apply", "120 routine"} {
		if !contains(got, want) {
			t.Errorf("audit answer missing %q: %s", want, got)
		}
	}
	// Routine noise must NOT appear as a change.
	if contains(got, "assistant.query") || contains(got, "certificate.issue") {
		t.Errorf("audit answer leaked routine noise: %s", got)
	}
	// Empty changes.
	if e := auditChangesDirectAnswer("what changed today", map[string]any{"changesByAction": map[string]int{}}); !contains(e, "No operator changes") {
		t.Errorf("empty audit answer wrong: %q", e)
	}
}

func TestMetricTrendDirectAnswer(t *testing.T) {
	base := time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC)
	hist := &MetricHistory{Hostname: "nas", WindowHours: 168, Metrics: []string{"disk"}, Points: []store.MetricHistoryPoint{
		{Time: base, DiskFreePctAvg: f64(31.8)},
		{Time: base.Add(48 * time.Hour), DiskFreePctAvg: f64(26.7)},
		{Time: base.Add(96 * time.Hour), DiskFreePctAvg: f64(29.1)},
	}}
	got := metricTrendDirectAnswer(hist)
	for _, want := range []string{"On nas over the past week", "disk-free fell from 31.8% to 29.1%", "min 26.7%", "max 31.8%"} {
		if !contains(got, want) {
			t.Errorf("trend answer missing %q: %s", want, got)
		}
	}
	if metricTrendDirectAnswer(&MetricHistory{Hostname: "x"}) != "" {
		t.Error("empty history should defer")
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
