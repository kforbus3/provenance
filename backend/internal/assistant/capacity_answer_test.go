package assistant

import (
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/insights"
)

func lowDisk(host string, free float64, trend string, runway *float64) insights.Insight {
	return insights.Insight{Severity: insights.SeverityWarning, Category: "disk", HostID: host + "-id", Hostname: host,
		Title: "Low disk space", Detail: "x", FreePct: &free, Trend: trend, RunwayDays: runway}
}

func runway(host string, days float64, conf string) insights.Insight {
	return insights.Insight{Severity: insights.SeverityWarning, Category: "disk-runway", HostID: host + "-id", Hostname: host,
		Title: "Disk filling up", Detail: "x", RunwayDays: &days, Confidence: conf}
}

func capPayload(days int, subject string, items ...insights.Insight) map[string]any {
	return map[string]any{"count": len(items), "horizonDays": days, "subject": subject, "items": items}
}

// The answer that prompted this: nas was 13% free -- a threshold warning, with no
// runway projection at all -- and Ask said it was "projected to run out of disk
// space within 7 days". Low now is not a forecast.
func TestCapacityAnswerLowDiskIsNotAForecast(t *testing.T) {
	got := capacityDirectAnswer(capPayload(7, "disk", lowDisk("nas", 13, insights.TrendSteady, nil)))
	want := "No host is projected to run out of disk space within the next 7 days. " +
		"Low on disk space right now: nas (13% free on its tightest filesystem; usage is steady, not trending toward full)."
	if got != want {
		t.Fatalf("answer:\n got  %q\n want %q", got, want)
	}
}

func TestCapacityAnswerSeparatesInsideAndOutsideTheWindow(t *testing.T) {
	got := capacityAnswer([]insights.Insight{
		runway("web", 3, "high"),
		runway("db", 10, "medium"),
		lowDisk("web", 4, insights.TrendFilling, f64(3)),
	}, 7, "disk")
	// Each sentence is matched whole, so db (10 days) cannot hide in the 7-day one.
	for _, want := range []string{
		"1 host is projected to run out of disk space within the next 7 days: web (fills in ~3 days at the recent rate, high confidence).",
		"Filling, but not within that window: db (fills in ~10 days at the recent rate, medium confidence).",
		// web's projection was already stated -- not repeated on its low-disk line.
		"Low on disk space right now: web (4% free on its tightest filesystem).",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// Runway insights only exist for hosts that fill within RunwayHorizonDays, so a
// 30-day question can only be answered for that horizon -- and must say so rather
// than claim nothing fills in 30 days.
func TestCapacityAnswerCapsTheHorizonOutLoud(t *testing.T) {
	got := capacityAnswer(nil, 30, "disk")
	want := "No host is projected to run out of disk space within the next 14 days " +
		"(the furthest ahead Provenance projects disk usage; you asked about 30). No host is low on disk space right now either."
	if got != want {
		t.Fatalf("answer:\n got  %q\n want %q", got, want)
	}
}

func TestCapacityAnswerLowDiskTrendClauses(t *testing.T) {
	got := capacityAnswer([]insights.Insight{
		lowDisk("a", 12, insights.TrendUnknown, nil),
		lowDisk("b", 9, insights.TrendFilling, f64(40)),
		lowDisk("c", 14, "", nil), // not analysed (over the per-computation cap)
	}, 7, "disk")
	for _, want := range []string{
		"a (12% free on its tightest filesystem; not enough recent history to project a trend)",
		"b (9% free on its tightest filesystem; filling slowly -- ~40 days at the recent rate)",
		"c (14% free on its tightest filesystem)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestCapacityAnswerMemory(t *testing.T) {
	mem := insights.Insight{Category: "memory", HostID: "ai-id", Hostname: "ai", Detail: "95% of memory in use."}
	got := capacityAnswer([]insights.Insight{mem}, 7, "disk or memory")
	for _, want := range []string{
		"No host is projected to run out of disk space within the next 7 days.",
		"High memory use right now (memory is not projected forward): ai (95% of memory in use).",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if got := capacityAnswer(nil, 7, "memory"); got != "No host is short of memory right now." {
		t.Errorf("memory-only empty answer = %q", got)
	}
}

func TestCapacityDirectAnswerDefersOnErrors(t *testing.T) {
	if got := capacityDirectAnswer(map[string]any{"error": "could not compute capacity outlook"}); got != "" {
		t.Errorf("error payload must defer to the model, got %q", got)
	}
	if got := capacityDirectAnswer("nope"); got != "" {
		t.Errorf("non-map payload must defer, got %q", got)
	}
}

// The question exactly as it was asked in Ask must reach this answer.
func TestCapacityQuestionAsAskedRoutesToCapacityOutlook(t *testing.T) {
	if name, _, ok := fastPathTool("are any hosts going to run out of space?"); !ok || name != "capacity_outlook" {
		t.Fatalf("routed to %q (ok=%v), want capacity_outlook", name, ok)
	}
}
