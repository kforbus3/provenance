package monitor

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/models"
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
	st, _, _ := m.probeConfirmed(context.Background(), h, "online", scriptedProbe(&calls, "offline", "online"))
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
	st, _, _ := m.probeConfirmed(context.Background(), h, "online", scriptedProbe(&calls, "offline"))
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
	st, _, _ := m.probeConfirmed(context.Background(), h, "offline", scriptedProbe(&calls, "offline"))
	if st.Status != "offline" || calls != 1 {
		t.Fatalf("status=%q calls=%d, want a single un-retried probe for an already-offline host", st.Status, calls)
	}
}

func TestProbeConfirmedNoRetryOnFirstObservation(t *testing.T) {
	m := testMonitor(3)
	h := &models.Host{Hostname: "wap"}
	calls := 0
	if st, _, _ := m.probeConfirmed(context.Background(), h, "", scriptedProbe(&calls, "offline")); st.Status != "offline" || calls != 1 {
		t.Fatalf("status=%q calls=%d, want single probe when there is no prior status", st.Status, calls)
	}
}

func TestProbeConfirmedOnlineNeverRetries(t *testing.T) {
	m := testMonitor(3)
	h := &models.Host{Hostname: "wap"}
	calls := 0
	if st, _, _ := m.probeConfirmed(context.Background(), h, "online", scriptedProbe(&calls, "online")); st.Status != "online" || calls != 1 {
		t.Fatalf("status=%q calls=%d, want single probe for a healthy host", st.Status, calls)
	}
}

func TestProbeConfirmedThresholdOneKeepsOldBehavior(t *testing.T) {
	m := testMonitor(1)
	h := &models.Host{Hostname: "wap"}
	calls := 0
	if st, _, _ := m.probeConfirmed(context.Background(), h, "online", scriptedProbe(&calls, "offline")); st.Status != "offline" || calls != 1 {
		t.Fatalf("status=%q calls=%d, want immediate flip with confirmations=1", st.Status, calls)
	}
}

func TestProbeConfirmedZeroConfigDefaultsToThree(t *testing.T) {
	m := testMonitor(0)
	if got := m.offlineConfirmations(); got != 3 {
		t.Fatalf("offlineConfirmations() = %d with unset config, want default 3", got)
	}
}
