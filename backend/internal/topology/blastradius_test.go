package topology

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/kforbus3/provenance/backend/internal/store"
)

var (
	nas        = uuid.New()
	hypervisor = uuid.New()
	guestA     = uuid.New()
	guestB     = uuid.New()
	guestC     = uuid.New()
)

func edge(dependent uuid.UUID, dependentName string, on uuid.UUID, onName, kind string) store.HostDependencyEdge {
	return store.HostDependencyEdge{
		HostID: dependent, Hostname: dependentName,
		DependsOnID: on, DependsOn: onName, Kind: kind,
	}
}

// The 2026-09-13 shape: the thing everything stands on is inside the batch, and
// most of what it carries is NOT. That is damage the operator did not ask for
// and cannot see from the list in front of them.
func TestDependentsOutsideTheSelectionAreCritical(t *testing.T) {
	sel := []uuid.UUID{nas, guestA}
	got := Analyze(sel, []store.HostDependencyEdge{
		edge(guestA, "guest-a", nas, "nas", "storage"),
		edge(guestB, "guest-b", nas, "nas", "storage"),
		edge(guestC, "guest-c", nas, "nas", "storage"),
	})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	f := got[0]
	if f.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical — two of three dependents were not selected", f.Severity)
	}
	if f.Outside != 2 || f.InSelection != 1 {
		t.Errorf("inSelection=%d outside=%d, want 1 and 2", f.InSelection, f.Outside)
	}
	if !strings.Contains(f.Message, "not in this selection") {
		t.Errorf("the message must say some dependents were not selected, got %q", f.Message)
	}
	// Storage is the kind whose failure does not look like itself; the message
	// has to say so or the operator will not recognise it when it happens.
	if !strings.Contains(f.Message, "every write blocks") {
		t.Errorf("a storage finding should describe the symptom, got %q", f.Message)
	}
}

// Everything affected was chosen, so nothing unexpected breaks — but the action
// will still pull the floor out from under its own later targets.
func TestDependentsEntirelyInsideTheSelectionAreAnOrderingWarning(t *testing.T) {
	sel := []uuid.UUID{nas, guestA, guestB}
	got := Analyze(sel, []store.HostDependencyEdge{
		edge(guestA, "guest-a", nas, "nas", "storage"),
		edge(guestB, "guest-b", nas, "nas", "storage"),
	})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Severity != SeverityWarning {
		t.Errorf("severity = %q, want warning", got[0].Severity)
	}
	if got[0].Outside != 0 {
		t.Errorf("outside = %d, want 0", got[0].Outside)
	}
	if !strings.Contains(got[0].Message, "order this runs in") {
		t.Errorf("it should say order decides the outcome, got %q", got[0].Message)
	}
}

// A converged box is both hypervisor and storage. Those break differently, so
// collapsing them into one finding would describe neither accurately.
func TestAHostThatIsBothHypervisorAndStorageReportsBoth(t *testing.T) {
	sel := []uuid.UUID{hypervisor, guestA}
	got := Analyze(sel, []store.HostDependencyEdge{
		edge(guestA, "guest-a", hypervisor, "hypervisor", "hypervisor"),
		edge(guestA, "guest-a", hypervisor, "hypervisor", "storage"),
	})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 (one per kind): %+v", len(got), got)
	}
	kinds := map[string]bool{got[0].Kind: true, got[1].Kind: true}
	if !kinds["hypervisor"] || !kinds["storage"] {
		t.Errorf("both kinds should be reported, got %v", kinds)
	}
}

// The whole point is not warning about things nobody touched.
func TestAnEdgePointingAtAnUnselectedHostIsNotReported(t *testing.T) {
	sel := []uuid.UUID{guestA}
	got := Analyze(sel, []store.HostDependencyEdge{
		edge(guestA, "guest-a", nas, "nas", "storage"), // nas is NOT selected
	})
	if len(got) != 0 {
		t.Errorf("selecting only a dependent should produce no findings, got %+v", got)
	}
}

func TestNoSelectionAndNoEdgesProduceNothing(t *testing.T) {
	if got := Analyze(nil, []store.HostDependencyEdge{edge(guestA, "a", nas, "nas", "storage")}); got != nil {
		t.Errorf("no selection should produce nothing, got %+v", got)
	}
	if got := Analyze([]uuid.UUID{nas}, nil); got != nil {
		t.Errorf("no edges should produce nothing, got %+v", got)
	}
}

// Critical must sort above warning, or the preview buries the dangerous line.
func TestCriticalFindingsSortFirst(t *testing.T) {
	sel := []uuid.UUID{nas, hypervisor, guestA, guestB}
	got := Analyze(sel, []store.HostDependencyEdge{
		// hypervisor: fully inside the selection -> warning
		edge(guestA, "guest-a", hypervisor, "hypervisor", "hypervisor"),
		edge(guestB, "guest-b", hypervisor, "hypervisor", "hypervisor"),
		// nas: one dependent outside -> critical
		edge(guestC, "guest-c", nas, "nas", "storage"),
	})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	if got[0].Severity != SeverityCritical {
		t.Errorf("critical must sort first, got %q then %q", got[0].Severity, got[1].Severity)
	}
}
