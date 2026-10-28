package store

import (
	"testing"

	"github.com/google/uuid"
)

// A later release under a different tag format is stored in its own column, and a
// re-check that no longer finds one clears it rather than leaving the old answer.
func TestImageUpdateNewerElsewhereIsStored(t *testing.T) {
	s, _, ctx := scheduleTestStore(t)
	repo := "test/" + uuid.NewString()

	find := func() ImageUpdate {
		t.Helper()
		all, err := s.ImageUpdates(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range all {
			if u.Repository == repo {
				return u
			}
		}
		t.Fatalf("no row for %s", repo)
		return ImageUpdate{}
	}

	if err := s.UpsertImageUpdate(ctx, ImageUpdate{Repository: repo, Tag: "10.11.11",
		Status: ImageStatusNewScheme, NewerElsewhere: "12.4"}); err != nil {
		t.Fatal(err)
	}
	if got := find(); got.NewerElsewhere != "12.4" || got.LatestTag != "" ||
		got.Status != ImageStatusNewScheme {
		t.Fatalf("stored %+v", got)
	}

	if err := s.UpsertImageUpdate(ctx, ImageUpdate{Repository: repo, Tag: "10.11.11",
		Status: ImageStatusCurrent}); err != nil {
		t.Fatal(err)
	}
	if got := find(); got.NewerElsewhere != "" {
		t.Fatalf("a re-check kept the stale answer: %+v", got)
	}
}
