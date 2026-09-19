package registry

import (
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/store"
)

func row(repo, tag, latest, status string) store.ImageUpdateRow {
	return store.ImageUpdateRow{
		ImageUpdate: store.ImageUpdate{Repository: repo, Tag: tag, LatestTag: latest, Status: status},
	}
}

// This fleet's Updates page offered postgres 16-alpine → 18-alpine and
// 17.11-alpine → 18.6-alpine as ordinary updates. A rollout refuses them, which is
// correct and far too late: the summary counted them so the number available never
// reached zero, and "roll out everything" included them -- and because the refusal
// rejects the whole request, one impossible row blocked the two real updates behind
// it. The list has to say so where it is read.
func TestAMajorVersionBumpIsNotOfferedAsAnUpdate(t *testing.T) {
	rows := []store.ImageUpdateRow{
		row("postgres", "16-alpine", "18-alpine", "update"),
		row("postgres", "17.11-alpine", "18.6-alpine", "update"),
		row("ghcr.io/headlamp-k8s/headlamp", "v0.43.0", "v0.45.0", "update"),
		row("guacamole/guacd", "1.5.5", "1.6.0", "update"),
	}
	markMigrations(rows)

	if rows[0].Status != "migration" || rows[1].Status != "migration" {
		t.Fatalf("postgres major bumps still read as updates: %q / %q", rows[0].Status, rows[1].Status)
	}
	// And it must say what to do instead, because "you cannot" is not an answer.
	if !strings.Contains(rows[0].Note, "pg_upgrade") && !strings.Contains(rows[0].Note, "dump") {
		t.Errorf("the note does not name the migration: %q", rows[0].Note)
	}
	// The real updates are untouched. Over-reaching here would hide work that can
	// be done, which is the opposite failure and just as bad.
	if rows[2].Status != "update" || rows[3].Status != "update" {
		t.Errorf("an ordinary update was marked a migration: %+v / %+v", rows[2], rows[3])
	}
}

// Only a bump that actually crosses a major version of a stateful image.
func TestOrdinaryRowsAreLeftAlone(t *testing.T) {
	rows := []store.ImageUpdateRow{
		row("postgres", "16.2-alpine", "16.9-alpine", "update"), // minor: fine
		row("postgres", "18-alpine", "17-alpine", "update"),     // downgrade: deliberate, not ours
		row("nginx", "1.24", "1.27", "update"),                  // stateless
		row("postgres", "16-alpine", "18-alpine", "current"),    // not an update at all
		row("postgres", "16-alpine", "", "update"),              // nothing newer named
	}
	markMigrations(rows)
	for i, r := range rows {
		if r.Status == "migration" {
			t.Errorf("row %d was wrongly marked a migration: %+v", i, r)
		}
	}
}
