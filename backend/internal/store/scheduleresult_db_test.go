package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kforbus3/provenance/backend/internal/db"
	"github.com/kforbus3/provenance/backend/internal/models"
)

func scheduleTestStore(t *testing.T) (*Store, *pgxpool.Pool, context.Context) {
	t.Helper()
	url := os.Getenv("PROV_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("no test database offered; run via `make test-db`")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &Store{pool: pool}, pool, ctx
}

func findSchedule(t *testing.T, s *Store, ctx context.Context, id uuid.UUID) *models.Schedule {
	t.Helper()
	all, err := s.ListSchedules(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, sc := range all {
		if sc.ID == id {
			return sc
		}
	}
	t.Fatalf("schedule %s not listed", id)
	return nil
}

// A scheduled vulnerability scan lost a host; by morning its failed record had been
// cleared from the failures list, and the schedule read "completed". A launched
// record that no longer exists is a failure, and the page must say how many of how
// many worked.
func TestAScheduledBatchWithAVanishedFailureIsNotCompleted(t *testing.T) {
	s, _, ctx := scheduleTestStore(t)
	var ids []uuid.UUID
	var hosts []string
	for i := 0; i < 3; i++ {
		h, err := s.CreateHost(ctx, HostInput{Hostname: "batch-" + uuid.NewString()[:8]})
		if err != nil {
			t.Fatal(err)
		}
		hosts = append(hosts, h.Hostname)
		id, err := s.CreateVulnScan(ctx, h.ID, nil, "test", true)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	for _, id := range ids[:2] {
		if err := s.CompleteVulnScan(ctx, id, VulnSummary{}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.FailVulnScan(ctx, ids[2], "dial jump host: connection reset by peer"); err != nil {
		t.Fatal(err)
	}

	sc, err := s.CreateSchedule(ctx, &models.Schedule{Name: "batch-" + uuid.NewString()[:8], Kind: "vulnscan",
		TargetKind: "group", Recurrence: models.Recurrence{Type: "daily", TimeOfDay: "06:00"}, Payload: []byte("{}")}, nil)
	if err != nil {
		t.Fatalf("create schedule: %v", err)
	}
	fired := time.Now().Truncate(time.Microsecond)
	if err := s.MarkScheduleFired(ctx, sc.ID, fired, "started", fired.Add(24*time.Hour), ids); err != nil {
		t.Fatal(err)
	}

	got := findSchedule(t, s, ctx, sc.ID)
	if got.LastOutcome != "failed" || got.LastRunTotal != 3 || got.LastRunOK != 2 {
		t.Fatalf("with one failure: outcome=%q ok=%d/%d, want failed 2/3", got.LastOutcome, got.LastRunOK, got.LastRunTotal)
	}
	failures, missing, err := s.FailedScheduledRuns(ctx, "vulnscan", ids)
	if err != nil || len(failures) != 1 || missing != 0 || failures[0].Host != hosts[2] {
		t.Fatalf("expected one named failure, got %+v missing=%d err=%v", failures, missing, err)
	}

	// Clear the failures list, as the UI's clear-failures action does.
	if _, err := s.DeleteFailedVulnScans(ctx); err != nil {
		t.Fatal(err)
	}
	got = findSchedule(t, s, ctx, sc.ID)
	if got.LastOutcome != "failed" {
		t.Fatalf("after the failure was cleared the batch read %q -- the vanished-failure bug", got.LastOutcome)
	}
	if _, missing, _ := s.FailedScheduledRuns(ctx, "vulnscan", ids); missing != 1 {
		t.Fatalf("expected the cleared record to count as missing, got %d", missing)
	}
}

// A CVE refresh creates no record, so it read "started" for ever. Its result is
// written onto the firing -- and only onto that firing.
func TestACVERefreshReportsItsResultOnItsOwnFiring(t *testing.T) {
	s, _, ctx := scheduleTestStore(t)
	sc, err := s.CreateSchedule(ctx, &models.Schedule{Name: "vulndb-" + uuid.NewString()[:8], Kind: "vulndb",
		TargetKind: "none", Recurrence: models.Recurrence{Type: "daily", TimeOfDay: "03:00"}, Payload: []byte("{}")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fired := time.Now().Truncate(time.Microsecond)
	if err := s.MarkScheduleFired(ctx, sc.ID, fired, "started", fired.Add(24*time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	if got := findSchedule(t, s, ctx, sc.ID); got.LastOutcome != "running" {
		t.Fatalf("a refresh in progress should read running, got %q", got.LastOutcome)
	}

	// A result for some other firing must not land.
	if matched, err := s.RecordScheduleResult(ctx, sc.ID, fired.Add(-time.Hour), "completed"); err != nil || matched {
		t.Fatalf("a result for an earlier firing was recorded (matched=%v err=%v)", matched, err)
	}
	if matched, err := s.RecordScheduleResult(ctx, sc.ID, fired, "failed: grype database: no route to host"); err != nil || !matched {
		t.Fatalf("the firing's own result was not recorded (matched=%v err=%v)", matched, err)
	}
	if got := findSchedule(t, s, ctx, sc.ID); got.LastOutcome != "failed" {
		t.Fatalf("a failed refresh read %q", got.LastOutcome)
	}
}
