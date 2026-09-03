package imaging

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/Moorgate/backend/internal/models"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func nowPlusAnHour() time.Time { return time.Now().Add(time.Hour) }

// The reconcile loop decides two things per machine: nudge it, or report on its
// behalf. Both were wrong in a way no compiler catches and no operator would
// see quickly.
//
// It used to build stub Machine records from the rollout's machine ids alone,
// which has no hostnames and no presence. Two consequences:
//
//   - correlation could only match hosts with an explicitly recorded pairing.
//     Most hosts are matched by name, so most of the fleet would never be
//     nudged -- the rollout would still finish, on the agent's own timer, and
//     the feature would look like it was working while doing nothing.
//   - settling could not tell a machine Flipside hears from from one it does
//     not, so Moorgate would report on machines that report perfectly well for
//     themselves, over SSH, every thirty seconds.
//
// These test the decision, not the SSH. What to do with a machine is the part
// that can be wrong; connecting to it is the monitor's well-trodden path.

// plan mirrors the loop's decision so it can be checked without a gateway,
// a database or a host to connect to.
type decision struct {
	nudge  []string
	settle []string
}

func planFor(hosts []models.Host, machines []Machine, waiting, inFlight map[string]bool) decision {
	links, _ := Correlate(hosts, machines)
	var d decision
	for _, l := range links {
		if l.Machine == nil || !l.Host.Enrolled || l.Host.InMaintenance() || l.Host.Protocol == "rdp" {
			continue
		}
		id := l.Machine.ID
		switch {
		case inFlight[id]:
			if l.Machine.Presence == "online" {
				continue
			}
			d.settle = append(d.settle, id)
		case waiting[id]:
			d.nudge = append(d.nudge, id)
		}
	}
	return d
}

func enrolled(name, machineID string) models.Host {
	h := models.Host{ID: uuid.New(), Hostname: name, Enrolled: true}
	h.Options.FlipsideMachineID = machineID
	return h
}

func TestAHostMatchedOnlyByNameIsStillNudged(t *testing.T) {
	// The defect: correlating against stub records built from rollout ids means
	// a machine has no hostname, so a host with no explicit pairing matches
	// nothing and is never nudged. The rollout still finishes on the agent's
	// own timer, so the feature looks like it works while doing nothing at all.
	hosts := []models.Host{enrolled("web01", "")}
	machines := []Machine{{ID: "aa:bb", Hostname: "web01", Presence: "online"}}
	d := planFor(hosts, machines, map[string]bool{"aa:bb": true}, nil)
	if len(d.nudge) != 1 {
		t.Fatalf("a host paired by hostname was not nudged: %+v", d)
	}
}

func TestAMachineFlipsideCanHearFromIsNotSpokenOver(t *testing.T) {
	// Its own check-in arrives on its own timer, and it is the machine's word
	// about itself. Reporting over it would be Moorgate opening an SSH
	// connection every thirty seconds to say something already known.
	hosts := []models.Host{enrolled("web01", "aa:bb")}
	machines := []Machine{{ID: "aa:bb", Hostname: "web01", Presence: "online"}}
	d := planFor(hosts, machines, nil, map[string]bool{"aa:bb": true})
	if len(d.settle) != 0 {
		t.Fatalf("settled a machine Flipside is hearing from: %+v", d)
	}
}

func TestAMachineFlipsideCannotHearFromIsReportedOn(t *testing.T) {
	// The whole reason the attested path exists: this machine installed an
	// update and has nowhere to say so, and the rollout would otherwise wait
	// for a check-in that can never arrive.
	for _, presence := range []string{"offline", "unknown", "stale"} {
		hosts := []models.Host{enrolled("web01", "aa:bb")}
		machines := []Machine{{ID: "aa:bb", Hostname: "web01", Presence: presence}}
		d := planFor(hosts, machines, nil, map[string]bool{"aa:bb": true})
		if len(d.settle) != 1 {
			t.Fatalf("presence %q: not reported on: %+v", presence, d)
		}
	}
}

func TestMachinesNoRolloutIsWaitingOnAreLeftAlone(t *testing.T) {
	// The loop is a response to an operator having started something, not a
	// periodic sweep of the fleet.
	hosts := []models.Host{enrolled("web01", "aa:bb")}
	machines := []Machine{{ID: "aa:bb", Hostname: "web01", Presence: "online"}}
	d := planFor(hosts, machines, nil, nil)
	if len(d.nudge) != 0 || len(d.settle) != 0 {
		t.Fatalf("acted on a machine no rollout was waiting on: %+v", d)
	}
}

func TestHostsThatCannotTakeAnUpdateAreSkipped(t *testing.T) {
	waiting := map[string]bool{"aa:bb": true}
	machines := []Machine{{ID: "aa:bb", Hostname: "web01", Presence: "online"}}

	unenrolled := enrolled("web01", "aa:bb")
	unenrolled.Enrolled = false
	if d := planFor([]models.Host{unenrolled}, machines, waiting, nil); len(d.nudge) != 0 {
		t.Fatal("nudged a host that is not enrolled, so there is no way to reach it")
	}

	windows := enrolled("web01", "aa:bb")
	windows.Protocol = "rdp"
	if d := planFor([]models.Host{windows}, machines, waiting, nil); len(d.nudge) != 0 {
		t.Fatal("nudged a Windows host, which has no SSH and no Flipside agent")
	}

	// Maintenance is an operator saying "leave this one alone", and an update
	// arriving during it is exactly what they meant to prevent.
	maint := enrolled("web01", "aa:bb")
	future := nowPlusAnHour()
	maint.MaintenanceUntil = &future
	if d := planFor([]models.Host{maint}, machines, waiting, nil); len(d.nudge) != 0 {
		t.Fatal("nudged a host in a maintenance window")
	}
}

func TestReconcileReadsTheFleetAndNotJustTheRollout(t *testing.T) {
	// Guards the shape of the fix rather than its effect: if reconcile stops
	// asking for the fleet view, it is back to stub records with no hostname
	// and no presence, and both defects above return silently.
	var sawFleet bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/rollouts":
			_, _ = w.Write([]byte(`{"rollouts":[{"id":"r-1","state":"running",
				"machines":{"aa:bb":{"state":"pending"}}}]}`))
		case "/api/fleet":
			sawFleet = true
			_, _ = w.Write([]byte(`{"machines":[]}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	s := &Service{
		client:   NewClient(srv.URL, "t", 0),
		log:      discardLogger(),
		nudgedAt: map[string]time.Time{},
		halted:   map[string]bool{},
	}
	// store is nil, so this panics if it gets as far as listing hosts -- which
	// it cannot, because the fleet view comes first and returns no machines.
	s.reconcile(context.Background())
	if !sawFleet {
		t.Fatal("reconcile did not read the fleet view, so it has no hostnames or presence to decide with")
	}
}
