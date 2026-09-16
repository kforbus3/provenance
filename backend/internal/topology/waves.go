package topology

import (
	"sort"

	"github.com/google/uuid"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// Waves orders a set of hosts so that nothing is touched before the things
// standing on it are finished.
//
// The direction is the one that is easy to get backwards. A host that CARRIES
// others goes LAST: reboot the NAS while its guests are still patching and their
// root filesystems vanish mid-run, which is exactly the failure this exists to
// prevent. So dependents come first and carriers come last.
//
// The result is the schedule an operator writes by hand today -- guests, then
// storage, then the jump host, then the hypervisor -- derived instead of timed.
// Hand-timing it means choosing gaps and hoping the earlier run fits inside its
// own, which is a race rather than an order.
//
// Only edges BETWEEN selected hosts matter. A guest that depends on a NAS which
// is not part of this run constrains nothing here: the NAS is not being touched.
//
// Hosts within a wave have no dependency on each other and can run together.
//
// Cycles cannot be recorded through the API, but this does not assume that --
// rows can predate the check or be written directly. Anything still unplaced
// when no further progress is possible is emitted as a final wave rather than
// dropped, because a host missing from a fleet upgrade is worse than one whose
// order could not be proven.
func Waves(selected []uuid.UUID, edges []store.HostDependencyEdge) [][]uuid.UUID {
	if len(selected) == 0 {
		return nil
	}
	inSel := make(map[uuid.UUID]bool, len(selected))
	for _, id := range selected {
		inSel[id] = true
	}

	// carriers[h] = what h stands on, restricted to the selection.
	// dependents[x] = who stands on x, restricted to the selection.
	carriers := map[uuid.UUID]map[uuid.UUID]bool{}
	dependents := map[uuid.UUID]map[uuid.UUID]bool{}
	for _, e := range edges {
		if !inSel[e.HostID] || !inSel[e.DependsOnID] || e.HostID == e.DependsOnID {
			continue
		}
		if carriers[e.HostID] == nil {
			carriers[e.HostID] = map[uuid.UUID]bool{}
		}
		carriers[e.HostID][e.DependsOnID] = true
		if dependents[e.DependsOnID] == nil {
			dependents[e.DependsOnID] = map[uuid.UUID]bool{}
		}
		dependents[e.DependsOnID][e.HostID] = true
	}

	// Peel off, repeatedly, every host that nothing still-unplaced depends on.
	placed := map[uuid.UUID]bool{}
	var waves [][]uuid.UUID
	remaining := append([]uuid.UUID{}, selected...)

	for len(remaining) > 0 {
		var wave, rest []uuid.UUID
		for _, h := range remaining {
			ready := true
			for d := range dependents[h] {
				if !placed[d] {
					// Something that stands on h has not gone yet, so h waits.
					ready = false
					break
				}
			}
			if ready {
				wave = append(wave, h)
			} else {
				rest = append(rest, h)
			}
		}
		if len(wave) == 0 {
			// No progress: every host left is inside a cycle. Emit them together
			// rather than looping forever or dropping them.
			sortIDs(rest)
			waves = append(waves, rest)
			return waves
		}
		sortIDs(wave)
		waves = append(waves, wave)
		for _, h := range wave {
			placed[h] = true
		}
		remaining = rest
	}
	return waves
}

// sortIDs keeps wave membership deterministic, so the same selection produces
// the same plan every time it is previewed and then run.
func sortIDs(ids []uuid.UUID) {
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
}
