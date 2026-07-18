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
