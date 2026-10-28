package store

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// questarr was pinned by digest after a broken :dev build, and from then on the
// Updates page never mentioned it: no tag, so nothing selected it. A pin nobody
// can see is a container nobody upgrades.
func TestADigestPinnedContainerHasARow(t *testing.T) {
	s, _, ctx := scheduleTestStore(t)
	h, err := s.CreateHost(ctx, HostInput{Hostname: "pin-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatal(err)
	}
	repo := "ghcr.io/test/" + uuid.NewString()[:8]
	dg := "sha256:9e179255fa24f2b553c81261d793d8edd1fc9f32cf029c9282dbe760a88b7b78"
	now := time.Now()
	if err := s.UpdateHostContainers(ctx, h.ID, models.HostInventory{
		Containers: []models.Container{{Name: "questarr", Image: repo + "@" + dg,
			Repository: repo, Tag: "", Digest: "sha256:2fb9"}},
		ContainersStatus: "ok", ContainersCheckedAt: &now}); err != nil {
		t.Fatal(err)
	}

	rows, err := s.ImageUpdatesWithHosts(ctx, "provenance")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Repository != repo {
			continue
		}
		if r.Status != ImageStatusPinned || r.Pinned != dg || r.Tag != "" || r.LatestTag != "" {
			t.Fatalf("row = %+v", r.ImageUpdate)
		}
		if len(r.Hosts) != 1 || r.Hosts[0].Container != "questarr" {
			t.Fatalf("hosts = %+v", r.Hosts)
		}
		return
	}
	t.Fatal("a digest-pinned container has no row on the Updates page")
}
