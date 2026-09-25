package store

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// A host whose last container stops must stop listing it; a host that could not be
// asked must keep what it last reported. Both rules live in COALESCE, so they are
// decided by nil versus empty -- which only SQL can say what it does with.
func TestAHostWhoseContainersStoppedStopsListingThem(t *testing.T) {
	s, pool, ctx := scheduleTestStore(t)
	h, err := s.CreateHost(ctx, HostInput{Hostname: "ctr-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO host_inventory (host_id) VALUES ($1) ON CONFLICT DO NOTHING`, h.ID); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		var n int
		if err := pool.QueryRow(ctx, `SELECT coalesce(jsonb_array_length(containers),0) FROM host_inventory WHERE host_id=$1`, h.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	now := time.Now()
	running := models.HostInventory{Containers: []models.Container{{Name: "docker-frontend-1", State: "restarting"}},
		ContainersStatus: "ok", ContainersCheckedAt: &now}
	if err := s.UpdateHostContainers(ctx, h.ID, running); err != nil {
		t.Fatal(err)
	}
	if count() != 1 {
		t.Fatal("setup: the container was not recorded")
	}

	// Could not ask: nil list. The last one stays.
	if err := s.UpdateHostContainers(ctx, h.ID, models.HostInventory{ContainersStatus: "unreachable", ContainersCheckedAt: &now}); err != nil {
		t.Fatal(err)
	}
	if count() != 1 {
		t.Fatal("a host that could not be asked lost its last list")
	}

	// Asked, and nothing is running: an empty list. It must replace the old one.
	if err := s.UpdateHostContainers(ctx, h.ID, models.HostInventory{Containers: []models.Container{},
		ContainersStatus: "ok", ContainersCheckedAt: &now}); err != nil {
		t.Fatal(err)
	}
	if count() != 0 {
		t.Fatal("a host with nothing running still lists the container that stopped")
	}
}
