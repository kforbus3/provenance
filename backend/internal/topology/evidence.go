// Package topology corroborates the recorded dependency graph against what the
// hosts themselves report.
//
// The graph in host_dependencies is asserted by an operator, and it has to be: no
// machine knows it is a guest of a particular hypervisor. But a hand-entered graph
// that nothing ever checks goes stale in silence -- a host gains an NFS mount,
// nobody records it, and the blast-radius preview and wave ordering built on that
// graph then state something false with complete confidence. That is worse than
// having no graph, because a warning that has been right nine times is believed the
// tenth.
//
// So this package reads the evidence Provenance already collects -- the mount table
// and the host's own answer to "am I virtualised" -- and reports three things: which
// recorded edges it can see for itself, which edges it can see that nobody has
// recorded, and which servers a host depends on that Provenance does not manage at
// all.
//
// It never writes an edge. Observing a mount is evidence; an edge is an assertion
// about the estate, and the operator makes it.
package topology

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// Dependency kinds this package can produce. They match the kinds the schema
// records, because a suggestion has to be acceptable as-is.
const (
	KindStorage    = "storage"
	KindHypervisor = "hypervisor"
)

// maxEvidenceMounts bounds how many mounts one evidence line names before it says
// "and N more". A host with thirty mounts from one server has one dependency, not
// thirty, and the sentence has to stay readable.
const maxEvidenceMounts = 3

// Suggestion is a dependency Provenance can see that nobody has recorded.
type Suggestion struct {
	DependsOnID uuid.UUID `json:"dependsOnId"`
	DependsOn   string    `json:"dependsOn"`
	Kind        string    `json:"kind"`
	Evidence    string    `json:"evidence"`
}

// Confirmation is a recorded edge this host's own report agrees with.
type Confirmation struct {
	DependsOnID uuid.UUID `json:"dependsOnId"`
	Kind        string    `json:"kind"`
	Evidence    string    `json:"evidence"`
}

// Unmanaged is a machine this host depends on that Provenance does not manage.
//
// Worth its own category: an edge cannot be recorded for it at all, so it is not a
// suggestion, and it is the one case where the graph cannot be made complete. A
// fleet whose storage comes from something outside the fleet has a blind spot that
// no amount of careful data entry will close.
type Unmanaged struct {
	Server   string `json:"server"`
	Evidence string `json:"evidence"`
}

// HostView is everything this package can say about one host's dependencies.
type HostView struct {
	Confirmations []Confirmation `json:"confirmations"`
	Suggestions   []Suggestion   `json:"suggestions"`
	Unmanaged     []Unmanaged    `json:"unmanaged"`
	// Collected is false when this host has never reported its mounts -- an old
	// agent-less host, or one that has not been swept since this was added. It is
	// the difference between "nothing to corroborate with" and "corroborated
	// nothing", and the UI must not render the first as the second.
	Collected bool `json:"collected"`
}

// ForHost corroborates one host's recorded dependencies.
//
// hosts is the fleet the caller can see (needed to turn a mount's server into a
// host, and to decide whether there is exactly one hypervisor), and recorded is
// what that host already stands on.
func ForHost(hostID uuid.UUID, hosts []models.Host, recorded []store.HostDependencyEdge) HostView {
	view := HostView{Confirmations: []Confirmation{}, Suggestions: []Suggestion{}, Unmanaged: []Unmanaged{}}

	var self *models.Host
	for i := range hosts {
		if hosts[i].ID == hostID {
			self = &hosts[i]
			break
		}
	}
	if self == nil {
		return view
	}
	view.Collected = self.Inventory != nil && self.Inventory.MountsCheckedAt != nil

	// What is already recorded, so an observation is either a confirmation or a
	// suggestion and never both.
	have := map[string]bool{}
	for _, e := range recorded {
		have[e.DependsOnID.String()+":"+e.Kind] = true
	}

	index := nameIndex(hosts)
	for _, obs := range observedFor(self, hosts, index) {
		switch {
		case obs.unmanagedServer != "":
			view.Unmanaged = append(view.Unmanaged, Unmanaged{Server: obs.unmanagedServer, Evidence: obs.evidence})
		case have[obs.targetID.String()+":"+obs.kind]:
			view.Confirmations = append(view.Confirmations,
				Confirmation{DependsOnID: obs.targetID, Kind: obs.kind, Evidence: obs.evidence})
		default:
			view.Suggestions = append(view.Suggestions, Suggestion{
				DependsOnID: obs.targetID, DependsOn: obs.targetName, Kind: obs.kind, Evidence: obs.evidence,
			})
		}
	}
	return view
}

// observation is one thing a host's own report says about what it stands on.
type observation struct {
	kind            string
	targetID        uuid.UUID
	targetName      string
	evidence        string
	unmanagedServer string // set instead of a target when the server is not a known host
}

// observedFor derives the observations for one host, ordered so the output is
// stable: storage (which a host can see for itself) before the hypervisor guess.
func observedFor(self *models.Host, hosts []models.Host, index map[string]*models.Host) []observation {
	var out []observation
	if self.Inventory != nil {
		// Group mounts by server: many mounts from one NAS are one dependency.
		type group struct {
			server string
			mounts []models.NetworkMount
		}
		order := []string{}
		byServer := map[string]*group{}
		for _, m := range self.Inventory.NetworkMounts {
			key := strings.ToLower(strings.TrimSpace(m.Server))
			if key == "" {
				continue
			}
			if byServer[key] == nil {
				byServer[key] = &group{server: key}
				order = append(order, key)
			}
			byServer[key].mounts = append(byServer[key].mounts, m)
		}
		sort.Strings(order)
		for _, key := range order {
			g := byServer[key]
			target := lookupServer(index, key)
			// A host mounting from itself (loopback NFS, or its own name) is not a
			// dependency on anything, and recording it would be a self-edge the
			// schema forbids anyway.
			if target != nil && target.ID == self.ID {
				continue
			}
			ev := mountEvidence(g.server, g.mounts)
			if target == nil {
				out = append(out, observation{unmanagedServer: g.server, evidence: ev})
				continue
			}
			out = append(out, observation{
				kind: KindStorage, targetID: target.ID, targetName: target.Hostname, evidence: ev,
			})
		}
	}
	if h, virt, ok := soleHypervisor(self, hosts); ok {
		out = append(out, observation{
			kind: KindHypervisor, targetID: h.ID, targetName: h.Hostname,
			evidence: fmt.Sprintf("reports running under %s, and %s is the only hypervisor in the fleet", virt, h.Hostname),
		})
	}
	return out
}

// mountEvidence writes the sentence that justifies a storage dependency.
func mountEvidence(server string, mounts []models.NetworkMount) string {
	var parts []string
	for i, m := range mounts {
		if i == maxEvidenceMounts {
			parts = append(parts, fmt.Sprintf("and %d more", len(mounts)-maxEvidenceMounts))
			break
		}
		parts = append(parts, fmt.Sprintf("%s on %s (%s)", m.Source, m.Target, m.FSType))
	}
	return "mounts " + strings.Join(parts, ", ")
}

// guestVirtTypes are the answers to systemd-detect-virt that mean "this is a virtual
// machine somebody else runs".
//
// Containers are deliberately absent. An LXC or Docker guest is not a host with a
// hypervisor edge -- it is a process on a machine that is usually already recorded
// some other way, and suggesting a hypervisor edge for every container host would
// fill the graph with relationships nobody asked about.
var guestVirtTypes = map[string]bool{
	"kvm": true, "qemu": true, "vmware": true, "microsoft": true, "xen": true,
	"bochs": true, "bhyve": true, "parallels": true, "oracle": true, "amazon": true, "apple": true,
}

// hypervisorPorts are what a machine that RUNS guests has bound: Proxmox's web UI,
// libvirt's TLS socket, ESXi's agent.
var hypervisorPorts = map[int]string{8006: "Proxmox", 16514: "libvirt", 16509: "libvirt", 902: "ESXi"}

// soleHypervisor returns the fleet's one hypervisor, when the guess is safe.
//
// Only when it is unambiguous. A guest knows it is virtualised and cannot know by
// whom: with one hypervisor in the fleet the answer is forced, and with two it is a
// coin toss that would be recorded as a fact and then read back as one by a preview
// that decides what to reboot. Two hypervisors means say nothing.
func soleHypervisor(self *models.Host, hosts []models.Host) (*models.Host, string, bool) {
	if self.Inventory == nil {
		return nil, "", false
	}
	virt := strings.ToLower(strings.TrimSpace(self.Inventory.Virtualisation))
	if !guestVirtTypes[virt] {
		return nil, "", false
	}
	var found *models.Host
	for i := range hosts {
		h := &hosts[i]
		if h.ID == self.ID || h.Inventory == nil {
			continue
		}
		// A guest is not somebody else's hypervisor here. Nested virtualisation
		// exists, and a lab that has it can record the edge by hand.
		if guestVirtTypes[strings.ToLower(strings.TrimSpace(h.Inventory.Virtualisation))] {
			continue
		}
		if !listensAsHypervisor(h) {
			continue
		}
		if found != nil {
			return nil, "", false // more than one candidate: no guess
		}
		found = h
	}
	if found == nil {
		return nil, "", false
	}
	return found, virt, true
}

// listensAsHypervisor reports whether a host has a hypervisor's management port
// bound. Loopback-only does not count: a hypervisor runs guests for other machines.
func listensAsHypervisor(h *models.Host) bool {
	for _, p := range h.Inventory.ListeningPorts {
		if _, ok := hypervisorPorts[p.Port]; ok && p.Exposed {
			return true
		}
	}
	return false
}

// lookupServer finds the host a mount's server names.
//
// The index holds each host's own spellings; this handles the other direction. An
// fstab written as "nas.example.com:/mnt/nas" has to find a host enrolled as "nas",
// which is what production actually looked like -- the first host to report a mount
// named the FQDN, and matching only the literal string would have reported the
// fleet's NAS as a machine Provenance does not manage.
func lookupServer(index map[string]*models.Host, server string) *models.Host {
	key := strings.ToLower(strings.TrimSpace(server))
	if h := index[key]; h != nil {
		return h
	}
	// Try the label before the domain. Only for something that looks like a name:
	// truncating an IPv4 address at its first dot would match a host called "10".
	if i := strings.Index(key, "."); i > 0 && net.ParseIP(key) == nil {
		return index[key[:i]]
	}
	return nil
}

// nameIndex maps every name a mount source might use to the host that answers to it.
//
// A mount is written however the person who wrote the fstab felt: the short name,
// the FQDN, the LAN address, or the overlay address. All four have to resolve to the
// same host or the evidence is missed and a dependency looks unrecorded.
func nameIndex(hosts []models.Host) map[string]*models.Host {
	idx := map[string]*models.Host{}
	add := func(key string, h *models.Host) {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			return
		}
		if _, taken := idx[key]; !taken {
			idx[key] = h
		}
	}
	for i := range hosts {
		h := &hosts[i]
		add(h.Hostname, h)
		if j := strings.Index(h.Hostname, "."); j > 0 {
			add(h.Hostname[:j], h)
		}
		add(h.Address, h)
		add(h.WGAddress, h)
	}
	return idx
}
