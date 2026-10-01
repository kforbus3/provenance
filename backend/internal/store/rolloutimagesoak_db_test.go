package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRolloutImageSoakStamps(t *testing.T) {
	s, _, ctx := scheduleTestStore(t)
	h, err := s.CreateHost(ctx, HostInput{Hostname: "soak-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.CreateUpdateRollout(ctx, UpdateRollout{
		Repository: "nginx", FromTag: "1.24", ToTag: "1.27", Canary: 1, BatchSize: 5, SoakSeconds: 300,
		Images: []RolloutImage{{Repository: "nginx", FromTag: "1.24", ToTag: "1.27"},
			{Repository: "redis", FromTag: "7", ToTag: "7.2"}},
	}, []uuid.UUID{h.ID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := time.Now().UTC().Truncate(time.Second)
	if err := s.StampRolloutImageCanaryDone(ctx, r.ID, "nginx", "1.24", first); err != nil {
		t.Fatal(err)
	}
	// A later stamp must not move it: that would restart the image's soak.
	if err := s.StampRolloutImageCanaryDone(ctx, r.ID, "nginx", "1.24", first.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkRolloutImageSoakChecked(ctx, r.ID, "nginx", "1.24", first.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkRolloutImageSoakChecked(ctx, r.ID, "caddy", "2", first); !errors.Is(err, ErrNotFound) {
		t.Fatalf("checking an image the rollout does not cover returned %v", err)
	}
	ims, err := s.RolloutImages(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]RolloutImage{}
	for _, im := range ims {
		by[im.Repository] = im
	}
	if n := by["nginx"]; n.CanaryDoneAt == nil || !n.CanaryDoneAt.Equal(first) || n.SoakCheckedAt == nil {
		t.Fatalf("nginx = %+v", n)
	}
	if rd := by["redis"]; rd.CanaryDoneAt != nil || rd.SoakCheckedAt != nil {
		t.Fatalf("redis was stamped by nginx's progress: %+v", rd)
	}
}
