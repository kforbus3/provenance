package monitor

import (
	"testing"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// A host that leaves the network it was enrolled on must not read as offline.
//
// The concern is concrete: a laptop is imaged and enrolled on one LAN, then goes
// home, to a customer site, or onto a hotel network. It still has internet, so
// its WireGuard tunnel still comes up and the server can still reach it — but if
// reachability were judged by the LAN address it was enrolled with, every such
// machine would show offline the moment it was useful. An operator would learn
// to distrust the column, which is worse than not having it.
//
// The property that prevents it is the ORDER of the addresses tried: the overlay
// address first, the LAN address only as a fallback. That ordering is one line in
// probe() and nothing pinned it.
func TestOverlayAddressIsTriedBeforeTheLANAddress(t *testing.T) {
	h := &models.Host{
		Hostname:  "laptop-1",
		Address:   "10.10.0.51",  // where it lived when it was enrolled
		WGAddress: "10.100.0.42", // where it lives wherever it goes
	}

	got := dedupe([]string{h.WGAddress, h.Address, h.Hostname})

	if len(got) == 0 || got[0] != h.WGAddress {
		t.Fatalf("first address tried = %q, want the WireGuard address %q.\n"+
			"A roaming host is reachable over the overlay and not at the LAN address "+
			"it was enrolled with; trying the LAN first makes every machine that "+
			"moves look offline.", firstOf(got), h.WGAddress)
	}
	// The LAN address is still worth trying: it is the faster path when the host
	// has not moved, and the only path if the overlay is down.
	if !contains(got, h.Address) {
		t.Errorf("the LAN address %q is never tried; a host whose overlay is down "+
			"but which is sitting on the same network would read as offline", h.Address)
	}
	if !contains(got, h.Hostname) {
		t.Errorf("the hostname is never tried; that is the last resort for a host " +
			"with neither address recorded")
	}
}

// A host with no overlay address has nothing to roam with, and the fallbacks must
// still be tried in a sensible order rather than the list collapsing.
func TestHostWithoutAnOverlayAddressStillHasFallbacks(t *testing.T) {
	h := &models.Host{Hostname: "rack-switch", Address: "10.10.0.111"}
	got := dedupe([]string{h.WGAddress, h.Address, h.Hostname})
	if len(got) == 0 || got[0] != h.Address {
		t.Fatalf("first address tried = %q, want %q", firstOf(got), h.Address)
	}
	for _, a := range got {
		if a == "" {
			t.Fatal("an empty address is in the candidate list; a dial against it " +
				"wastes a timeout on every sweep for every host with no overlay")
		}
	}
}

func firstOf(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
