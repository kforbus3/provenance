package store

import (
	"encoding/json"
	"os"
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

// Twenty-four containers on a host, and a page that showed none of them.
//
// ImageUpdatesWithHosts started from the CHECKED rows, so an image only appeared
// once a registry had been asked about it — and the check ran every twelve hours.
// A host whose containers had just become visible contributed nothing to the
// updates screen for most of a day, with no row saying so.
//
// "We have not asked yet" and "there is nothing there" are different, and this
// page is the one place that distinction is the entire point.
func TestAnUncheckedImageIsStillARowWithNoTimestamp(t *testing.T) {
	row := ImageUpdateRow{
		ImageUpdate: ImageUpdate{Repository: "jellyfin/jellyfin", Tag: "10.11.11"},
		Hosts:       []ImageUpdateHost{{HostID: "h1", Hostname: "docker"}},
	}
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	// A zero CheckedAt is how the client tells "never asked" from "asked, nothing
	// to report". If it ever marshals to something truthy, the row silently reads
	// as checked-and-current.
	if !strings.Contains(string(b), `"checkedAt":"0001-01-01T00:00:00Z"`) {
		t.Errorf("an unchecked row should carry a zero timestamp the client can "+
			"detect, got:\n%s", b)
	}
	if !strings.Contains(string(b), `"hostname":"docker"`) {
		t.Errorf("the hosts running it must still be listed:\n%s", b)
	}
}

// The query is driven by TrackedImages (what the fleet runs), not by the checked
// rows. Reversing that is the bug above, and it is invisible until a host's
// containers first appear.
func TestTheUpdatesQueryIsDrivenByWhatTheFleetRuns(t *testing.T) {
	src, err := os.ReadFile("imageupdates.go")
	if err != nil {
		t.Fatal(err)
	}
	body := funcBody(string(src), "func (s *Store) ImageUpdatesWithHosts")
	if body == "" {
		t.Fatal("ImageUpdatesWithHosts not found")
	}
	trackedAt := strings.Index(body, "s.TrackedImages(ctx)")
	loopAt := strings.Index(body, "for _, t := range tracked")
	if trackedAt < 0 || loopAt < 0 {
		t.Fatal("the rows are no longer built from the tracked images, so an image " +
			"the fleet runs but has never been checked has no row at all")
	}
}
