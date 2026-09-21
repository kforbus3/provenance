package winrm

import (
	"reflect"
	"testing"
)

// Fetching an enrollment script must not take the host out of management.
//
// The script has to contain the overlay address the host will hold, so fetching one
// assigns and persists that address immediately. The host does not join the overlay
// until somebody runs the script on it and pastes the public key back — minutes later
// at best, often the next day. Every WinRM path preferred the overlay address the
// moment it was set, so in between, a host that was answering perfectly well on its
// ordinary address failed everything with:
//
//	no reachable WinRM port: ssh: rejected: connect failed ("No route to host")
//
// Reproduced on a live Windows Server 2025 host: an automation ran fine, an enrollment
// script was fetched and deliberately not finished, and the identical automation failed.
func TestAnUnenrolledHostIsNotManagedOverTheOverlay(t *testing.T) {
	got := ManagementAddrs("10.100.0.2", "10.10.0.199", "prov-win-qa", false)
	want := []string{"10.10.0.199", "prov-win-qa"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("a host that has not joined the overlay is managed over it: got %v, want %v.\n"+
			"Its assigned overlay address has no peer behind it until enrollment finishes, so "+
			"every WinRM call fails with 'No route to host' against a host that is answering "+
			"normally on %s", got, want, "10.10.0.199")
	}
	if first := ManagementAddr("10.100.0.2", "10.10.0.199", "prov-win-qa", false); first != "10.10.0.199" {
		t.Errorf("the single-address callers still dial %q", first)
	}
}

// Once it IS enrolled the overlay comes first, which is the point of the overlay:
// it is the path that works when the ordinary address is not routable from here.
func TestAnEnrolledHostPrefersTheOverlay(t *testing.T) {
	got := ManagementAddrs("10.100.0.2", "10.10.0.199", "prov-win-qa", true)
	want := []string{"10.100.0.2", "10.10.0.199", "prov-win-qa"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// A remote host reachable ONLY over the overlay must not be left with nothing.
func TestAnOverlayOnlyHostStillHasAnAddress(t *testing.T) {
	if got := ManagementAddrs("10.100.0.2", "", "", true); !reflect.DeepEqual(got, []string{"10.100.0.2"}) {
		t.Errorf("got %v", got)
	}
	// Even unenrolled, an address is better than none: the caller fails either way,
	// but with nothing it cannot even report what it tried.
	if got := ManagementAddrs("10.100.0.2", "", "", false); !reflect.DeepEqual(got, []string{"10.100.0.2"}) {
		t.Errorf("got %v", got)
	}
}

// Duplicates collapse — a host whose hostname IS its address should be dialled once.
func TestDuplicateAddressesCollapse(t *testing.T) {
	if got := ManagementAddrs("", "10.10.0.199", "10.10.0.199", false); !reflect.DeepEqual(got, []string{"10.10.0.199"}) {
		t.Errorf("got %v", got)
	}
}
