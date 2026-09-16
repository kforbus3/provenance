package topology

import (
	"testing"

	"github.com/google/uuid"
	"github.com/kforbus3/provenance/backend/internal/store"
)

func waveOf(waves [][]uuid.UUID, id uuid.UUID) int {
	for i, w := range waves {
		for _, h := range w {
			if h == id {
				return i
			}
		}
	}
	return -1
}

// The homelab, and the direction that is easy to get backwards.
//
// Guests stand on both the hypervisor and the NAS. Touch the NAS while the
// guests are still patching and their root filesystems vanish mid-run. So the
// guests go FIRST and the things carrying them go last.
func TestCarriersGoAfterEverythingThatStandsOnThem(t *testing.T) {
	nasID, vhostID := uuid.New(), uuid.New()
	g1, g2 := uuid.New(), uuid.New()
	sel := []uuid.UUID{nasID, vhostID, g1, g2}
	edges := []store.HostDependencyEdge{
		{HostID: g1, DependsOnID: nasID, Kind: "storage"},
		{HostID: g2, DependsOnID: nasID, Kind: "storage"},
		{HostID: g1, DependsOnID: vhostID, Kind: "hypervisor"},
		{HostID: g2, DependsOnID: vhostID, Kind: "hypervisor"},
	}
	w := Waves(sel, edges)
	if len(w) != 2 {
		t.Fatalf("got %d waves, want 2: %v", len(w), w)
	}
	if waveOf(w, g1) != 0 || waveOf(w, g2) != 0 {
		t.Errorf("guests must go first, got g1=%d g2=%d", waveOf(w, g1), waveOf(w, g2))
	}
	if waveOf(w, nasID) != 1 || waveOf(w, vhostID) != 1 {
		t.Errorf("carriers must go last, got nas=%d hypervisor=%d", waveOf(w, nasID), waveOf(w, vhostID))
	}
}

// A chain has to produce a chain: storage under a hypervisor under a guest.
func TestAChainProducesOneWavePerLevel(t *testing.T) {
	guest, hv, st := uuid.New(), uuid.New(), uuid.New()
	w := Waves([]uuid.UUID{guest, hv, st}, []store.HostDependencyEdge{
		{HostID: guest, DependsOnID: hv, Kind: "hypervisor"},
		{HostID: hv, DependsOnID: st, Kind: "storage"},
	})
	if len(w) != 3 {
		t.Fatalf("got %d waves, want 3: %v", len(w), w)
	}
	if waveOf(w, guest) != 0 || waveOf(w, hv) != 1 || waveOf(w, st) != 2 {
		t.Errorf("wrong order: guest=%d hv=%d storage=%d",
			waveOf(w, guest), waveOf(w, hv), waveOf(w, st))
	}
}

// An edge to something NOT being touched constrains nothing.
func TestAnEdgeToAnUnselectedHostDoesNotSplitTheRun(t *testing.T) {
	g1, g2, outside := uuid.New(), uuid.New(), uuid.New()
	w := Waves([]uuid.UUID{g1, g2}, []store.HostDependencyEdge{
		{HostID: g1, DependsOnID: outside, Kind: "storage"},
		{HostID: g2, DependsOnID: outside, Kind: "storage"},
	})
	if len(w) != 1 {
		t.Fatalf("got %d waves, want 1 — the NAS is not in this run: %v", len(w), w)
	}
}

// Hosts with no recorded topology behave exactly as they do today: one wave,
// all together. The feature must not slow down a fleet that has recorded nothing.
func TestNoEdgesMeansOneWave(t *testing.T) {
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	w := Waves([]uuid.UUID{a, b, c}, nil)
	if len(w) != 1 || len(w[0]) != 3 {
		t.Fatalf("got %v, want a single wave of 3", w)
	}
}

// Cycles cannot be entered through the API, but rows can predate that check or
// be written directly. A host missing from a fleet upgrade is worse than one
// whose order could not be proven.
func TestACycleStillEmitsEveryHost(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	w := Waves([]uuid.UUID{a, b}, []store.HostDependencyEdge{
		{HostID: a, DependsOnID: b, Kind: "other"},
		{HostID: b, DependsOnID: a, Kind: "other"},
	})
	var n int
	for _, wave := range w {
		n += len(wave)
	}
	if n != 2 {
		t.Errorf("a cycle dropped hosts: got %d of 2 in %v", n, w)
	}
}

func TestWavesAreDeterministic(t *testing.T) {
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	edges := []store.HostDependencyEdge{{HostID: ids[0], DependsOnID: ids[3], Kind: "storage"}}
	first := Waves(ids, edges)
	for i := 0; i < 5; i++ {
		if got := Waves(ids, edges); !sameWaves(got, first) {
			t.Fatalf("run %d differed:\n%v\n%v", i, got, first)
		}
	}
}

func sameWaves(a, b [][]uuid.UUID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}
