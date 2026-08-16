package monitor

import (
	"testing"
	"time"

	"github.com/kforbus3/Moorgate/backend/internal/config"
)

// TestNextSweepGap verifies the adaptive cadence: a quick sweep idles the remainder
// of the target window, a sweep that fills the window re-probes at the floor, and an
// instantaneous/empty sweep never dips below the floor (no busy-loop).
func TestNextSweepGap(t *testing.T) {
	cases := []struct {
		name            string
		target, elapsed time.Duration
		want            time.Duration
	}{
		{"quick sweep idles remainder", 30 * time.Second, 5 * time.Second, 25 * time.Second},
		{"instant sweep floors", 30 * time.Second, 0, 30 * time.Second},
		{"full sweep floors at min", 30 * time.Second, 30 * time.Second, minSweepGap},
		{"over-long sweep floors at min", 30 * time.Second, 5 * time.Minute, minSweepGap},
		{"just under floor remaining floors", 30 * time.Second, 29 * time.Second, minSweepGap},
	}
	for _, c := range cases {
		if got := nextSweepGap(c.target, c.elapsed); got != c.want {
			t.Errorf("%s: nextSweepGap(%v,%v)=%v, want %v", c.name, c.target, c.elapsed, got, c.want)
		}
	}
}

// TestMonitorConcurrencyClamp verifies the configured worker-pool size is clamped
// to [1, maxMonitorConcurrency] with the documented default when unset, so a large
// fleet can raise throughput up to the safe ceiling but a fat-fingered value can't
// exceed what the jump host will accept.
func TestMonitorConcurrencyClamp(t *testing.T) {
	cases := []struct {
		configured, want int
	}{
		{0, defaultMonitorConcurrency},
		{-5, defaultMonitorConcurrency},
		{1, 1},
		{10, 10},
		{maxMonitorConcurrency, maxMonitorConcurrency},
		{maxMonitorConcurrency + 100, maxMonitorConcurrency},
	}
	for _, c := range cases {
		m := &Monitor{cfg: &config.Config{MonitorConcurrency: c.configured}}
		if got := m.monitorConcurrency(); got != c.want {
			t.Errorf("MonitorConcurrency=%d: got %d, want %d", c.configured, got, c.want)
		}
	}
}
