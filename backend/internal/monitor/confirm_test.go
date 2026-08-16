package monitor

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/kforbus3/Moorgate/backend/internal/config"
	"github.com/kforbus3/Moorgate/backend/internal/models"
)

// testMonitor builds a Monitor with just enough wiring for probeConfirmed:
// confirmations configured, zero delay so tests run instantly.
func testMonitor(confirmations int) *Monitor {
	return &Monitor{
		cfg: &config.Config{MonitorOfflineConfirmations: confirmations, MonitorConfirmDelay: 0},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// scriptedProbe returns a run func that yields the given statuses in order,
// repeating the last one, and counts invocations.
func scriptedProbe(calls *int, statuses ...string) func() (models.HostStatus, *models.HostInventory, *models.HostMetrics) {
	return func() (models.HostStatus, *models.HostInventory, *models.HostMetrics) {
		i := *calls
		if i >= len(statuses) {
			i = len(statuses) - 1
		}
		*calls++
		return models.HostStatus{Status: statuses[i], LastError: "e" + statuses[i]}, nil, nil
	}
}

func TestProbeConfirmedTransientBlipStaysOnline(t *testing.T) {
	m := testMonitor(3)
	h := &models.Host{Hostname: "wap"}
	calls := 0
	st, _, _ := m.probeConfirmed(context.Background(), h, "online", false, scriptedProbe(&calls, "offline", "online"))
	if st.Status != "online" {
		t.Fatalf("status = %q, want online after a transient failure", st.Status)
	}
	if calls != 2 {
		t.Fatalf("probe ran %d times, want 2 (initial + one confirming retry)", calls)
	}
}

func TestProbeConfirmedRealOutageFlipsAfterAllAttempts(t *testing.T) {
	m := testMonitor(3)
	h := &models.Host{Hostname: "wap"}
	calls := 0
	st, _, _ := m.probeConfirmed(context.Background(), h, "online", false, scriptedProbe(&calls, "offline"))
	if st.Status != "offline" {
		t.Fatalf("status = %q, want offline after all attempts fail", st.Status)
	}
	if calls != 3 {
		t.Fatalf("probe ran %d times, want 3 consecutive failures before flipping", calls)
	}
}

func TestProbeConfirmedNoRetryWhenAlreadyOffline(t *testing.T) {
	m := testMonitor(3)
	h := &models.Host{Hostname: "wap"}
	calls := 0
	st, _, _ := m.probeConfirmed(context.Background(), h, "offline", false, scriptedProbe(&calls, "offline"))
	if st.Status != "offline" || calls != 1 {
		t.Fatalf("status=%q calls=%d, want a single un-retried probe for an already-offline host", st.Status, calls)
	}
}

func TestProbeConfirmedNoRetryOnFirstObservation(t *testing.T) {
	m := testMonitor(3)
	h := &models.Host{Hostname: "wap"}
	calls := 0
	if st, _, _ := m.probeConfirmed(context.Background(), h, "", false, scriptedProbe(&calls, "offline")); st.Status != "offline" || calls != 1 {
		t.Fatalf("status=%q calls=%d, want single probe when there is no prior status", st.Status, calls)
	}
}

func TestProbeConfirmedOnlineNeverRetries(t *testing.T) {
	m := testMonitor(3)
	h := &models.Host{Hostname: "wap"}
	calls := 0
	if st, _, _ := m.probeConfirmed(context.Background(), h, "online", false, scriptedProbe(&calls, "online")); st.Status != "online" || calls != 1 {
		t.Fatalf("status=%q calls=%d, want single probe for a healthy host", st.Status, calls)
	}
}

func TestProbeConfirmedThresholdOneKeepsOldBehavior(t *testing.T) {
	m := testMonitor(1)
	h := &models.Host{Hostname: "wap"}
	calls := 0
	if st, _, _ := m.probeConfirmed(context.Background(), h, "online", false, scriptedProbe(&calls, "offline")); st.Status != "offline" || calls != 1 {
		t.Fatalf("status=%q calls=%d, want immediate flip with confirmations=1", st.Status, calls)
	}
}

func TestProbeConfirmedZeroConfigDefaultsToThree(t *testing.T) {
	m := testMonitor(0)
	if got := m.offlineConfirmations(); got != 3 {
		t.Fatalf("offlineConfirmations() = %d with unset config, want default 3", got)
	}
}

// scriptedWGProbe yields online statuses whose WGOK follows the given sequence,
// repeating the last value, and counts invocations.
func scriptedWGProbe(calls *int, wgOK ...bool) func() (models.HostStatus, *models.HostInventory, *models.HostMetrics) {
	return func() (models.HostStatus, *models.HostInventory, *models.HostMetrics) {
		i := *calls
		if i >= len(wgOK) {
			i = len(wgOK) - 1
		}
		*calls++
		return models.HostStatus{Status: "online", WGOK: wgOK[i]}, nil, nil
	}
}

func TestProbeConfirmedTransientOverlayBlipStaysUp(t *testing.T) {
	m := testMonitor(3)
	h := &models.Host{Hostname: "repo", WGAddress: "10.100.0.23"}
	calls := 0
	st, _, _ := m.probeConfirmed(context.Background(), h, "online", true, scriptedWGProbe(&calls, false, true))
	if !st.WGOK {
		t.Fatalf("WGOK = false, want true after a transient overlay failure")
	}
	if calls != 2 {
		t.Fatalf("probe ran %d times, want 2 (initial + one confirming retry)", calls)
	}
}

func TestProbeConfirmedRealOverlayOutageFlipsAfterAllAttempts(t *testing.T) {
	m := testMonitor(3)
	h := &models.Host{Hostname: "repo", WGAddress: "10.100.0.23"}
	calls := 0
	st, _, _ := m.probeConfirmed(context.Background(), h, "online", true, scriptedWGProbe(&calls, false))
	if st.WGOK {
		t.Fatalf("WGOK = true, want false after all attempts fail")
	}
	if calls != 3 {
		t.Fatalf("probe ran %d times, want 3 consecutive failures before flipping", calls)
	}
}

func TestProbeConfirmedNoRetryWhenOverlayAlreadyDown(t *testing.T) {
	m := testMonitor(3)
	h := &models.Host{Hostname: "repo", WGAddress: "10.100.0.23"}
	calls := 0
	if st, _, _ := m.probeConfirmed(context.Background(), h, "online", false, scriptedWGProbe(&calls, false)); st.WGOK || calls != 1 {
		t.Fatalf("WGOK=%v calls=%d, want a single un-retried probe when the overlay was already down", st.WGOK, calls)
	}
}

func TestProbeConfirmedNoOverlayRetryWithoutWGAddress(t *testing.T) {
	m := testMonitor(3)
	h := &models.Host{Hostname: "bastion"} // direct/skip-WireGuard host: WGOK is always false
	calls := 0
	if _, _, _ = m.probeConfirmed(context.Background(), h, "online", true, scriptedWGProbe(&calls, false)); calls != 1 {
		t.Fatalf("probe ran %d times, want 1 for a host not enrolled in the overlay", calls)
	}
}
