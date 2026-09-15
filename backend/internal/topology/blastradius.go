// Package topology answers what a bulk action will actually reach.
//
// Hosts are selected as a flat list, but they stand on each other. A selection
// of fifteen looks like fifteen independent machines right up until one of them
// turns out to be serving the other thirteen their root filesystems.
//
// This produces the sentence an operator needs BEFORE confirming, not the
// post-mortem afterwards.
package topology

import (
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// Severity orders findings for display. A preview that buries the dangerous line
// under informational ones has not warned anybody.
type Severity string

const (
	// SeverityCritical: the action is self-defeating or will take out hosts the
	// operator did not select.
	SeverityCritical Severity = "critical"
	// SeverityWarning: the action is survivable but order matters.
	SeverityWarning Severity = "warning"
)

// Finding is one thing worth saying about a selection.
type Finding struct {
	Severity Severity `json:"severity"`
	// Kind is the dependency kind that produced it: hypervisor, storage, network
	// or other. Carried so a UI can group, and because storage reads differently
	// from the rest.
	Kind string `json:"kind"`
	// HostID/Hostname is the SELECTED host that others stand on.
	HostID   uuid.UUID `json:"hostId"`
	Hostname string    `json:"hostname"`
	// Dependents are the hostnames that stand on it, sorted.
	Dependents []string `json:"dependents"`
	// InSelection is how many of those dependents are themselves in this action.
	InSelection int `json:"inSelection"`
	// Outside is how many are not -- hosts the operator did not choose and may
	// not realise they are about to affect.
	Outside int    `json:"outside"`
	Message string `json:"message"`
}

// consequence describes what losing a host of this kind does to something
// standing on it. Phrased as the symptom, not the mechanism, because the
// symptom is what an operator will actually see and fail to recognise.
func consequence(kind string, n int) string {
	hosts := "host"
	if n != 1 {
		hosts = "hosts"
	}
	switch kind {
	case "hypervisor":
		return fmt.Sprintf("%d %s run on it as guests and stop entirely when it does", n, hosts)
	case "storage":
		return fmt.Sprintf("%d %s have their disks served by it — they keep answering the "+
			"network while every write blocks, so this does not present as a storage failure",
			n, hosts)
	case "network":
		return fmt.Sprintf("%d %s route or resolve through it", n, hosts)
	default:
		return fmt.Sprintf("%d %s depend on it", n, hosts)
	}
}

// Analyze reports what touching `selected` reaches, given every edge pointing at
// those hosts.
//
// Two distinct things are worth saying, and conflating them would lose the more
// serious one:
//
//   - Dependents OUTSIDE the selection are collateral. The operator chose N hosts
//     and is about to affect more than N. Critical: it is damage they did not ask
//     for and cannot see from the list they are looking at.
//
//   - Dependents INSIDE the selection are an ordering hazard. Everything affected
//     was chosen, so nothing unexpected is harmed -- but the action will pull the
//     floor out from under its own later targets, which is how a fleet upgrade
//     takes out the storage it is still running on. A warning, not a critical.
//
// A host that is both is reported once, at the higher severity, with both counts.
func Analyze(selected []uuid.UUID, edges []store.HostDependencyEdge) []Finding {
	if len(selected) == 0 || len(edges) == 0 {
		return nil
	}
	inSel := make(map[uuid.UUID]bool, len(selected))
	for _, id := range selected {
		inSel[id] = true
	}

	// Grouped by the selected host being stood on, per kind: a converged box that
	// is both hypervisor and storage produces two findings, because the two have
	// different consequences and collapsing them would describe neither.
	type key struct {
		host uuid.UUID
		kind string
	}
	type agg struct {
		hostname string
		inside   []string
		outside  []string
	}
	groups := map[key]*agg{}
	for _, e := range edges {
		if !inSel[e.DependsOnID] {
			// An edge pointing at a host nobody selected is not this action's
			// business.
			continue
		}
		k := key{e.DependsOnID, e.Kind}
		g := groups[k]
		if g == nil {
			g = &agg{hostname: e.DependsOn}
			groups[k] = g
		}
		if inSel[e.HostID] {
			g.inside = append(g.inside, e.Hostname)
		} else {
			g.outside = append(g.outside, e.Hostname)
		}
	}

	var out []Finding
	for k, g := range groups {
		all := append(append([]string{}, g.inside...), g.outside...)
		sort.Strings(all)
		f := Finding{
			Kind:        k.kind,
			HostID:      k.host,
			Hostname:    g.hostname,
			Dependents:  all,
			InSelection: len(g.inside),
			Outside:     len(g.outside),
		}
		if len(g.outside) > 0 {
			f.Severity = SeverityCritical
			f.Message = fmt.Sprintf(
				"%s is in this action, and %s. %d of them are not in this selection.",
				g.hostname, consequence(k.kind, len(all)), len(g.outside))
		} else {
			f.Severity = SeverityWarning
			f.Message = fmt.Sprintf(
				"%s is in this action, and %s — all of them also in this selection, so the "+
					"order this runs in decides whether they survive it.",
				g.hostname, consequence(k.kind, len(all)))
		}
		out = append(out, f)
	}

	// Critical first, then by breadth, then by name so the order is stable for a
	// UI and for tests.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity == SeverityCritical
		}
		if len(out[i].Dependents) != len(out[j].Dependents) {
			return len(out[i].Dependents) > len(out[j].Dependents)
		}
		if out[i].Hostname != out[j].Hostname {
			return out[i].Hostname < out[j].Hostname
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}
