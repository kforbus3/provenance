package store

import (
	"os"
	"strings"
	"testing"
)

// Seven hosts lost the reason they were not reporting containers.
//
// UpsertInventory wrote containers_status straight through. That was right while
// it was the only writer: "why we cannot see the containers" is current news even
// when the list itself is stale, so it should overwrite.
//
// It stopped being right when containers moved to their own ten-minute cadence.
// This path now runs WITHOUT collecting them, so an hourly inventory refresh
// whose container check was not due wrote an EMPTY status over a real one:
//
//	before   docker|no_access|16:02   coder|no_access|16:02   grafana|no_docker
//	after    docker|ok|16:29          coder|<empty>|16:22     grafana|<empty>
//
// An empty status renders as no container section at all, so the host simply
// looked like it had nothing to say — the same "silence reads as an answer"
// failure this column exists to prevent.
func TestAnInventoryRefreshDoesNotBlankTheContainerStatus(t *testing.T) {
	src, err := os.ReadFile("hosts.go")
	if err != nil {
		t.Fatal(err)
	}
	body := funcBody(string(src), "func (s *Store) UpsertInventory")
	if body == "" {
		t.Fatal("UpsertInventory not found")
	}

	for _, col := range []string{"containers_status", "containers_detail"} {
		// Written straight through: the bug.
		if strings.Contains(body, col+"=EXCLUDED."+col+",") {
			t.Errorf("%s is written unconditionally — a refresh that did not collect "+
				"containers blanks it, and the host loses the reason it is not reporting", col)
		}
		// Guarded on empty: a real status still overwrites, an absent one does not.
		want := "NULLIF(EXCLUDED." + col + ", '')"
		if !strings.Contains(body, want) {
			t.Errorf("%s is not guarded with %s", col, want)
		}
	}

	// The LIST keeps its own rule: a sweep that could not reach the socket must
	// not blank what a sweep that could collected.
	if !strings.Contains(body, "containers=COALESCE(EXCLUDED.containers, host_inventory.containers)") {
		t.Error("the container list is no longer preserved when a sweep returns none")
	}
}

// The narrow writer is the one that always has a freshly collected status, so it
// writes straight through. If it ever stopped, an unreachable host would keep a
// stale "ok" forever.
func TestTheNarrowWriterStillOverwritesTheStatus(t *testing.T) {
	src, _ := os.ReadFile("hosts.go")
	body := funcBody(string(src), "func (s *Store) UpdateHostContainers")
	if body == "" {
		t.Fatal("UpdateHostContainers not found")
	}
	if !strings.Contains(body, "containers_status = $4") {
		t.Error("the container-only writer no longer sets the status unconditionally; " +
			"a host that stopped answering would keep its last good status")
	}
}

// Forty images were reported "built locally — nothing to compare against" when
// they were ordinary registry images. They had been checked during a window when
// container digests were not being collected at all, and "built locally" is
// concluded from a MISSING digest — so the verdict was right about the input and
// wrong about the world.
//
// The freshness rule then held it: a row with no error is not re-checked for
// twelve hours, so correcting the collection did not correct the conclusions. The
// updates page showed one actionable image out of forty-eight.
func TestAnImageWithNoDigestIsAlwaysRechecked(t *testing.T) {
	src, err := os.ReadFile("imageupdates.go")
	if err != nil {
		t.Fatal(err)
	}
	body := funcBody(string(src), "func (s *Store) StaleImageChecks")
	if body == "" {
		t.Fatal("StaleImageChecks not found")
	}
	if !strings.Contains(body, "current_digest <> ''") {
		t.Error("a row with no digest is treated as fresh, so a 'built locally' " +
			"verdict survives the digests arriving — for twelve hours, per image")
	}
	// The freshness rule itself must still apply to rows that DO have a digest,
	// or every pass re-asks every registry and the rate limit is the ceiling.
	if !strings.Contains(body, "checked_at > now()") {
		t.Error("the freshness window is gone; every pass would re-ask every registry")
	}
}
