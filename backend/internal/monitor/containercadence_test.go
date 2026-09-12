package monitor

import (
	"strings"
	"testing"
	"time"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// The bug this file exists for.
//
// collectContainers was called only from collectInventory, which runs at most
// once an hour and is gated on collected_at. On the release that introduced
// container detection, every host already had fresh inventory from the version
// before it — so the gate was false, containers were never collected, and the
// fleet showed one host's containers and nothing else. The one host that worked
// was the one whose hourly refresh happened to fall after the upgrade.
//
// Nothing failed. There was no error to find: a collector had simply inherited a
// cadence chosen for kernel versions.

func TestContainersAreCollectedEvenWhenInventoryIsFresh(t *testing.T) {
	now := time.Now()
	fresh := models.HostInventory{CollectedAt: &now} // facts collected a moment ago

	if inventoryStale(&fresh) {
		t.Fatal("fixture is wrong: this inventory should not be stale")
	}
	// The whole point: inventory being fresh must not decide this.
	if !containersStale(&fresh) {
		t.Error("a host whose containers were NEVER collected was treated as current " +
			"because its other facts were fresh — this is the bug that made the " +
			"container feature look empty on the release that added it")
	}
}

func TestContainersGoStaleFasterThanInventory(t *testing.T) {
	// A kernel version changes at a reboot; what a host runs changes whenever
	// somebody deploys. A rollout picks its targets from this list, so it must not
	// be allowed to age like a fact that rarely moves.
	if containersTTL >= inventoryTTL {
		t.Errorf("containersTTL (%s) must be shorter than inventoryTTL (%s)",
			containersTTL, inventoryTTL)
	}

	at := func(d time.Duration) *models.HostInventory {
		t := time.Now().Add(-d)
		return &models.HostInventory{ContainersCheckedAt: &t}
	}
	if containersStale(at(containersTTL / 2)) {
		t.Error("re-collected well inside the TTL")
	}
	if !containersStale(at(containersTTL + time.Minute)) {
		t.Error("did not re-collect past the TTL")
	}
	if !containersStale(nil) {
		t.Error("a host with no inventory at all must be collected")
	}
}

func TestCollectInventoryDoesNotCollectContainers(t *testing.T) {
	// Re-coupling them would restore the original bug silently: containers would
	// still appear, just never on their own cadence, and only this test would say
	// so. Asserted against the source because the alternative is an SSH host.
	src := readSource(t, "monitor.go")
	body := between(src, "func collectInventory(", "\n}")
	if strings.Contains(body, "collectContainers(") {
		t.Error("collectInventory calls collectContainers again — containers are " +
			"back on the hourly inventory cadence, which is the bug in " +
			"TestContainersAreCollectedEvenWhenInventoryIsFresh")
	}
}

func TestContainersAreWrittenThroughTheNarrowUpdate(t *testing.T) {
	// UpsertInventory overwrites os_name/kernel_version unconditionally and sets
	// collected_at=now(). Routing a container-only collection through it would
	// blank the host's facts AND keep pushing collected_at forward, so the
	// inventory refresh those facts depend on would never come due again — a
	// fleet whose OS versions quietly stop updating.
	src := readSource(t, "monitor.go")
	body := between(src, "func (m *Monitor) probe(", "\n// ")
	i := strings.Index(body, "containersStale(")
	if i < 0 {
		t.Fatal("the probe no longer collects containers on their own cadence")
	}
	block := body[i:]
	if end := strings.Index(block, "\n\t}"); end > 0 {
		block = block[:end]
	}
	if !strings.Contains(block, "UpdateHostContainers(") {
		t.Error("container-only collection must use UpdateHostContainers, not UpsertInventory")
	}
	if strings.Contains(block, "UpsertInventory(") {
		t.Error("container-only collection went through UpsertInventory, which " +
			"blanks host facts and defers the inventory refresh forever")
	}
}
