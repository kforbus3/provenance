package scheduler

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// The refresh must not start inside Fire. Its result is written onto the schedule
// row, and the caller records the firing on that row after Fire returns -- so work
// already running could finish first and be overwritten with "started". This
// engine has no scanner: if Fire started the refresh, it would panic here.
func TestARefreshStartsOnlyAfterTheFiringIsRecorded(t *testing.T) {
	e := &Engine{}
	sc := &models.Schedule{ID: uuid.New(), Kind: "vulndb", Name: "VulnDBUpdate"}
	status, ids, then := e.Fire(context.Background(), sc)
	if status != "started" || ids != nil {
		t.Fatalf("got %q %v", status, ids)
	}
	if then == nil {
		t.Fatal("a refresh must hand back its work to start after the firing is recorded")
	}
}

func TestABatchFailureNamesEachHostAndItsReason(t *testing.T) {
	sc := &models.Schedule{Name: "VulnScan"}
	title, body := batchFailureMessage(sc, "vulnscan", 17,
		[]store.ScheduledRunFailure{{Host: "gitlab", Error: "collect packages: dial jump host: connection reset by peer"}}, 1)
	if !strings.Contains(title, "2 of 17") || !strings.Contains(title, "Vulnerability scan") {
		t.Errorf("title should count failures of the total: %q", title)
	}
	for _, want := range []string{"gitlab: collect packages", "no longer exist"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
}
