package store

import (
	"os"
	"strings"
	"testing"
)

// The mount table is evidence behind a dependency edge, and it follows the same
// contract as every other collected list here: NULL means "this sweep did not ask".
//
// Written straight through, an inventory refresh on a host that was briefly
// unreachable -- or one whose mount collection failed -- would blank it, and the
// Dependencies panel would then say the host reports no network storage. That is a
// false statement about the estate produced by a failure to ask, and it would quietly
// withdraw the corroboration from an edge that is still perfectly real.
func TestMountEvidenceIsPreservedWhenASweepCannotAsk(t *testing.T) {
	src, err := os.ReadFile("hosts.go")
	if err != nil {
		t.Fatal(err)
	}
	body := funcBody(string(src), "func (s *Store) UpsertInventory")
	if body == "" {
		t.Fatal("UpsertInventory not found")
	}
	for _, col := range []string{"network_mounts", "mounts_checked_at"} {
		if strings.Contains(body, col+"=EXCLUDED."+col+",") {
			t.Errorf("%s is written unconditionally — a sweep that could not read the mount "+
				"table blanks it, and the host then reports no network storage", col)
		}
		want := "COALESCE(EXCLUDED." + col + ", host_inventory." + col + ")"
		if !strings.Contains(body, want) {
			t.Errorf("%s is not preserved with %s", col, want)
		}
	}
	// Virtualisation is a single value rather than a list, so it takes the same rule
	// the container status takes: an empty answer must not overwrite a real one.
	if !strings.Contains(body, "virtualisation=COALESCE(NULLIF(EXCLUDED.virtualisation, ''), host_inventory.virtualisation)") {
		t.Error("virtualisation is not guarded against being blanked by a sweep that could not detect it")
	}
}

// Collecting a column and never selecting it is a specific kind of silent failure:
// everything works, nothing errors, and every host reports it has no network mounts
// forever. The read has to name the columns the write fills.
func TestTheInventoryReadSelectsTheMountEvidence(t *testing.T) {
	src, err := os.ReadFile("hosts.go")
	if err != nil {
		t.Fatal(err)
	}
	// attachHostDetailsBatch is the one place inventory is read back, for both the
	// list and the single-host paths.
	body := funcBody(string(src), "func (s *Store) attachHostDetailsBatch")
	if body == "" {
		t.Fatal("attachHostDetailsBatch not found")
	}
	for _, col := range []string{"network_mounts", "mounts_checked_at", "virtualisation"} {
		if !strings.Contains(body, col) {
			t.Errorf("the inventory SELECT does not read %s — it is collected and stored, "+
				"and every host will report having none", col)
		}
	}
}
