package scheduler

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/kforbus3/provenance/backend/internal/models"
)

func stages(n int) []stage {
	out := make([]stage, n)
	for i := range out {
		out[i] = stage{id: uuid.New()}
	}
	return out
}

// run/status recorders shared by the tests below.
type recorder struct {
	ran      []uuid.UUID
	statuses map[uuid.UUID]string
	errs     map[uuid.UUID]error
	warns    int
}

func (r *recorder) run(s stage) { r.ran = append(r.ran, s.id) }
func (r *recorder) status(id uuid.UUID) (string, error) {
	if err, ok := r.errs[id]; ok {
		return "", err
	}
	return r.statuses[id], nil
}
func (r *recorder) warn(string, ...any) { r.warns++ }

func TestEveryWaveRunsWhenEachOneCompletes(t *testing.T) {
	st := stages(3)
	r := &recorder{statuses: map[uuid.UUID]string{}}
	for _, s := range st {
		r.statuses[s.id] = models.PlaybookRunCompleted
	}
	runStages(st, r.run, r.status, r.warn)

	if len(r.ran) != 3 {
		t.Fatalf("ran %d waves, want 3", len(r.ran))
	}
	// Order is the whole point: dependents first, carriers last.
	for i := range st {
		if r.ran[i] != st[i].id {
			t.Errorf("wave %d ran out of order", i+1)
		}
	}
	if r.warns != 0 {
		t.Errorf("warned %d times on a clean run", r.warns)
	}
}

// The reason ordering exists. If patching the guests went wrong, rebooting the
// storage they stand on is the last thing that should happen next.
func TestAFailedWaveStopsTheOnesBehindIt(t *testing.T) {
	st := stages(3)
	r := &recorder{statuses: map[uuid.UUID]string{
		st[0].id: models.PlaybookRunCompleted,
		st[1].id: models.PlaybookRunFailed,
		st[2].id: models.PlaybookRunCompleted, // must never be reached
	}}
	runStages(st, r.run, r.status, r.warn)

	if len(r.ran) != 2 {
		t.Fatalf("ran %d waves, want 2 — the third stands on the one that failed", len(r.ran))
	}
	if r.warns == 0 {
		t.Error("halting silently is indistinguishable from finishing")
	}
}

func TestAnInterruptedWaveAlsoStops(t *testing.T) {
	st := stages(2)
	r := &recorder{statuses: map[uuid.UUID]string{
		st[0].id: models.PlaybookRunInterrupted,
		st[1].id: models.PlaybookRunCompleted,
	}}
	runStages(st, r.run, r.status, r.warn)
	if len(r.ran) != 1 {
		t.Fatalf("ran %d waves, want 1", len(r.ran))
	}
}

// Not knowing whether a wave succeeded is not permission to continue.
func TestAnUnreadableWaveResultStops(t *testing.T) {
	st := stages(2)
	r := &recorder{
		statuses: map[uuid.UUID]string{st[1].id: models.PlaybookRunCompleted},
		errs:     map[uuid.UUID]error{st[0].id: errors.New("database gone")},
	}
	runStages(st, r.run, r.status, r.warn)
	if len(r.ran) != 1 {
		t.Fatalf("ran %d waves, want 1 — an unknown result must not let the next wave go", len(r.ran))
	}
	if r.warns == 0 {
		t.Error("an unreadable result must be reported")
	}
}

// The bug this package actually shipped: the gate was written against the status
// "success", which this system never writes. Every sequence would have stopped
// after its first wave, silently, looking exactly like a fleet that stopped
// early on purpose. It was caught by querying the database, not by a test.
func TestTheCompletedStatusIsTheOneTheRunnerActuallyWrites(t *testing.T) {
	if models.PlaybookRunCompleted != "completed" {
		t.Fatalf("PlaybookRunCompleted = %q; the runner writes \"completed\"",
			models.PlaybookRunCompleted)
	}
	for _, wrong := range []string{"success", "ok", "done", "succeeded"} {
		if models.PlaybookRunCompleted == wrong {
			t.Errorf("gating on %q would halt every sequence after its first wave", wrong)
		}
	}
	st := stages(2)
	r := &recorder{statuses: map[uuid.UUID]string{
		st[0].id: "success", // a plausible word this system never writes
		st[1].id: models.PlaybookRunCompleted,
	}}
	runStages(st, r.run, r.status, r.warn)
	if len(r.ran) != 1 {
		t.Error("a status the runner never writes must not be treated as success")
	}
}

func TestNoStagesIsNotAFailure(t *testing.T) {
	r := &recorder{statuses: map[uuid.UUID]string{}}
	runStages(nil, r.run, r.status, r.warn)
	if len(r.ran) != 0 || r.warns != 0 {
		t.Error("an empty sequence should do nothing quietly")
	}
}
