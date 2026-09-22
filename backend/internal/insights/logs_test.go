package insights

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/logsbroker"
	"github.com/kforbus3/provenance/backend/internal/models"
)

type fakeRates struct {
	rates []logsbroker.HostErrorRate
	err   error
	calls int
}

func (f *fakeRates) ErrorRates(context.Context, int, int) ([]logsbroker.HostErrorRate, error) {
	f.calls++
	return f.rates, f.err
}

func rate(host string, recent, baseline int) logsbroker.HostErrorRate {
	return logsbroker.HostErrorRate{
		Host: host, Recent: recent, Baseline: baseline,
		RecentMinutes: 60, BaselineMinutes: 7*24*60 - 60,
	}
}

// The rule has two halves and both must bind. A host that always logs loudly is
// not news (the dashboard becomes noise and gets ignored); a host that went from
// nothing to a trickle is not news either.
func TestLogSpikeNeedsBothAVolumeAndARatio(t *testing.T) {
	// Steady and loud: 200/h now, and it has been ~200/h all week. Not a spike.
	steady := rate("builder", 200, 200*167)
	if _, _, ok := logSpike(steady); ok {
		t.Error("a host that always logs 200 errors an hour was reported as a spike")
	}
	// A real spike: 120 in the last hour against roughly 1/hour all week.
	spike := rate("hypervisor", 120, 167)
	title, detail, ok := logSpike(spike)
	if !ok {
		t.Fatal("120 errors/hour against a 1/hour baseline was not reported")
	}
	if title == "" || !strings.Contains(detail, "120 errors") {
		t.Errorf("card does not say what was seen: %q / %q", title, detail)
	}
	// The card must carry the comparison, because "120 errors" alone is not
	// actionable -- the operator's next question is always "is that a lot?".
	if !strings.Contains(detail, "×") || !strings.Contains(detail, "/min") {
		t.Errorf("card does not quantify the comparison: %q", detail)
	}
	// Below the floor: 4x its baseline, but only 8 errors an hour. Not worth a card.
	if _, _, ok := logSpike(rate("nas", 8, 334)); ok {
		t.Error("8 errors an hour was reported")
	}
}

// A host with no errors at all in its history has no ratio to compute; dividing by
// that zero would report every such host as an infinite spike (or NaN, which
// compares false and reports none of them). It gets its own sentence instead.
func TestLogSpikeHandlesAnEmptyBaseline(t *testing.T) {
	_, detail, ok := logSpike(rate("keycloak", 60, 0))
	if !ok {
		t.Fatal("a host with a clean week and 60 errors this hour was not reported")
	}
	if !strings.Contains(detail, "none at all") {
		t.Errorf("detail should say the baseline was empty, got %q", detail)
	}
	// ...and the floor still applies to it.
	if _, _, ok := logSpike(rate("keycloak", 3, 0)); ok {
		t.Error("3 errors against an empty baseline was reported")
	}
}

// Matching log senders to hosts: Aldgate shortens names, so a host enrolled with a
// domain must still match, and access must not leak.
func TestLogInsightsMatchHostsAndRespectAccess(t *testing.T) {
	svc := &Service{log: slog.New(slog.DiscardHandler)}
	id := uuid.New()
	hosts := []models.Host{{ID: id, Hostname: "hypervisor.example.com"}}
	svc.logs = &fakeRates{rates: []logsbroker.HostErrorRate{
		rate("hypervisor", 120, 167), // the short name of a host we can see
		rate("coreswitch", 300, 200), // a sender with no host record
	}}

	got := svc.logInsights(context.Background(), hosts, true)
	if len(got) != 2 {
		t.Fatalf("super admin got %d insights, want 2: %+v", len(got), got)
	}
	if got[0].HostID != id.String() || got[0].Hostname != "hypervisor.example.com" {
		t.Errorf("short log name did not match the enrolled host: %+v", got[0])
	}
	if got[1].Hostname != "coreswitch" || got[1].HostID != "" {
		t.Errorf("unmanaged sender should be reported by its log name with no host id: %+v", got[1])
	}
	if got[0].Category != "logs" || got[0].Severity != SeverityWarning {
		t.Errorf("wrong category/severity: %+v", got[0])
	}

	// A non-super-admin sees only senders that map to a host they can access: an
	// unmatched sender has no host record to check access against, so reporting it
	// would hand out the name of a device the user may have no business seeing.
	got = svc.logInsights(context.Background(), hosts, false)
	if len(got) != 1 || got[0].HostID != id.String() {
		t.Fatalf("scoped user got %+v, want only the host they can access", got)
	}
}

// A host being patched logs errors by design. It is silenced everywhere else in
// this package, and a log card would walk straight through that.
func TestLogInsightsSkipMaintenance(t *testing.T) {
	until := time.Now().Add(time.Hour)
	svc := &Service{log: slog.New(slog.DiscardHandler)}
	svc.logs = &fakeRates{rates: []logsbroker.HostErrorRate{rate("hypervisor", 120, 167)}}
	hosts := []models.Host{{ID: uuid.New(), Hostname: "hypervisor", MaintenanceUntil: &until}}
	if got := svc.logInsights(context.Background(), hosts, true); len(got) != 0 {
		t.Fatalf("host in maintenance produced %+v", got)
	}
}

// A collector that is down must cost the dashboard nothing but these cards.
func TestLogInsightsSurviveACollectorFailure(t *testing.T) {
	svc := &Service{log: slog.New(slog.DiscardHandler)}
	svc.logs = &fakeRates{err: errors.New("dial tcp: connection refused")}
	if got := svc.logInsights(context.Background(), nil, true); len(got) != 0 {
		t.Fatalf("expected no insights, got %+v", got)
	}
}

// New returns a nil *Client when no collector is configured. Assigning that
// straight to the interface field would make it non-nil, and Compute would then
// call through a nil pointer and panic on every dashboard load.
func TestSetLogSourceRejectsATypedNil(t *testing.T) {
	svc := &Service{log: slog.New(slog.DiscardHandler)}
	svc.SetLogSource(logsbroker.New("", "", ""))
	if svc.logs != nil {
		t.Fatal("an unconfigured collector became a non-nil log source; Compute would panic")
	}
}
