package insights

import (
	"math"
	"testing"
)

func TestLinregFitsAKnownLine(t *testing.T) {
	// y = -2x + 100 (disk free falling 2%/day from 100%).
	xs := []float64{0, 1, 2, 3, 4}
	ys := []float64{100, 98, 96, 94, 92}
	slope, intercept, r2, ok := linreg(xs, ys)
	if !ok {
		t.Fatal("expected ok")
	}
	if math.Abs(slope-(-2)) > 1e-9 {
		t.Fatalf("slope = %v, want -2", slope)
	}
	if math.Abs(intercept-100) > 1e-9 {
		t.Fatalf("intercept = %v, want 100", intercept)
	}
	if math.Abs(r2-1) > 1e-9 {
		t.Fatalf("r2 = %v, want 1 for a perfect line", r2)
	}
}

func TestLinregRejectsZeroVariance(t *testing.T) {
	// All x identical: slope is undefined.
	if _, _, _, ok := linreg([]float64{3, 3, 3}, []float64{1, 2, 3}); ok {
		t.Fatal("expected ok=false for zero x-variance")
	}
}

func TestSeverityRankOrdersCriticalFirst(t *testing.T) {
	if !(severityRank(SeverityCritical) < severityRank(SeverityWarning) &&
		severityRank(SeverityWarning) < severityRank(SeverityInfo)) {
		t.Fatal("severity ranking is not critical < warning < info")
	}
}

func TestProjectRunwayTrends(t *testing.T) {
	// Flat at 13% free for a week: low, but not filling (the nas case).
	if _, _, trend := projectRunway([]float64{0, 1, 2, 3, 4, 5, 6}, []float64{13, 13, 13.1, 13, 12.98, 13, 13}); trend != TrendSteady {
		t.Errorf("flat series: trend = %q, want %q", trend, TrendSteady)
	}
	// Too few samples to fit anything.
	if _, _, trend := projectRunway([]float64{0, 1, 2}, []float64{20, 18, 16}); trend != TrendUnknown {
		t.Errorf("3 samples: trend = %q, want %q", trend, TrendUnknown)
	}
	// Falling 2%/day, now at 12%: full in ~6 days, perfect fit.
	days, conf, trend := projectRunway([]float64{0, 1, 2, 3, 4}, []float64{20, 18, 16, 14, 12})
	if trend != TrendFilling || conf != "high" || math.Abs(days-6) > 1e-9 {
		t.Errorf("falling series: days=%v conf=%q trend=%q, want 6 high filling", days, conf, trend)
	}
	// Already projected at or below zero: filling, zero days left.
	if days, _, trend := projectRunway([]float64{0, 1, 2, 3}, []float64{6, 4, 2, 0}); trend != TrendFilling || days != 0 {
		t.Errorf("exhausted series: days=%v trend=%q, want 0 filling", days, trend)
	}
}
