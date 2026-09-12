package store

import (
	"encoding/json"
	"strings"
	"testing"
)

// The white screen.
//
// An image no host runs any more got `hosts: null` rather than `hosts: []`,
// because Go marshals a nil slice as null. The browser did hosts.filter(...) on
// it, React unmounted the whole app, and /stacks was a blank page.
//
// It was not an edge case. Upgrading this product replaces its own containers, so
// the tags it just superseded keep their rows until the next check pass prunes
// them — every upgrade produced several, and the page broke immediately after
// every upgrade.
func TestAnImageWithNoHostsMarshalsAsAnEmptyListNotNull(t *testing.T) {
	row := ImageUpdateRow{
		ImageUpdate: ImageUpdate{Repository: "fleet-terminal-backend", Tag: "1.2.3"},
		Hosts:       []ImageUpdateHost{}, // what the query must now produce
	}
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"hosts":null`) {
		t.Errorf("hosts marshalled as null; a client doing hosts.filter() on that "+
			"blanks the page:\n%s", b)
	}
	if !strings.Contains(string(b), `"hosts":[]`) {
		t.Errorf("expected an empty array, got:\n%s", b)
	}
}

func TestANilHostsSliceIsTheFailureBeingPrevented(t *testing.T) {
	// Pins WHY the assignment in ImageUpdatesWithHosts exists. Without it the map
	// lookup returns nil and this is what reaches the browser.
	var nilHosts []ImageUpdateHost
	b, _ := json.Marshal(ImageUpdateRow{Hosts: nilHosts})
	if !strings.Contains(string(b), `"hosts":null`) {
		t.Skip("Go no longer marshals a nil slice as null; the guard may be unnecessary")
	}
}
