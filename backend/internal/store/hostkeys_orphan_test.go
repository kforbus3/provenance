package store

import (
	"reflect"
	"testing"
)

// Deleting a host must take its SSH host-key pins with it.
//
// ssh_host_keys is keyed by the TEXT a host is dialled as — overlay address,
// management address, hostname — because that is what the gateway holds when it
// verifies a key. So no foreign key reaches it, nothing cascaded, and every
// deleted host left its pins behind: nine of forty-three on a real deployment.
//
// The consequence is not untidiness. An overlay address is allocated by scanning
// hosts.wg_address for what is in use, so deleting a host returns its address to
// the pool. The next host enrolled can be handed it, present its own key, be
// compared against the dead host's pin, and be refused with
//
//	host key for <host> does not match the pinned key
//	(possible MITM, or the host was rebuilt — remove its pin to re-trust)
//
// on a host that was never rebuilt and is not under attack. The message sends
// whoever reads it hunting an intrusion.
//
// The deletion itself needs a database. What is checked here is the part that
// silently goes wrong: which identities get cleaned up.

func TestEveryDialableIdentityIsCleanedUp(t *testing.T) {
	got := hostIdentities("10.100.0.25", "192.168.1.5", "imager")
	want := []string{"10.100.0.25", "192.168.1.5", "imager"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("identities = %v, want %v — a host is pinned under each address it "+
			"can be dialled as, so missing one leaves a pin nothing will clean up", got, want)
	}
}

// A host with no overlay address, or no management address, is ordinary — most
// have exactly one. Empty values must not become an empty-string identity, which
// would match the pin of anything else stored with a blank host.
func TestBlankIdentitiesAreNotCleanedUp(t *testing.T) {
	for _, tc := range []struct {
		name             string
		wg, addr, hostnm string
		want             []string
	}{
		{"overlay only", "10.100.0.25", "", "", []string{"10.100.0.25"}},
		{"hostname only", "", "", "imager", []string{"imager"}},
		{"no identity at all", "", "", "", nil},
		{"overlay and name", "10.101.0.2", "", "alma1", []string{"10.101.0.2", "alma1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := hostIdentities(tc.wg, tc.addr, tc.hostnm)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("identities = %v, want %v", got, tc.want)
			}
			for _, id := range got {
				if id == "" {
					t.Error("an empty identity would match unrelated pins stored blank")
				}
			}
		})
	}
}
