package scheduler

import (
	"errors"
	"strings"
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
	skips    map[uuid.UUID]string
}

func (r *recorder) run(s stage) { r.ran = append(r.ran, s.id) }
func (r *recorder) status(id uuid.UUID) (string, error) {
	if err, ok := r.errs[id]; ok {
		return "", err
	}
	return r.statuses[id], nil
}
func (r *recorder) warn(string, ...any) { r.warns++ }

// skipped records the waves that were closed out without running, and why.
func (r *recorder) skip(st stage, reason string) {
	if r.skips == nil {
		r.skips = map[uuid.UUID]string{}
	}
	r.skips[st.id] = reason
}

func TestEveryWaveRunsWhenEachOneCompletes(t *testing.T) {
	st := stages(3)
	r := &recorder{statuses: map[uuid.UUID]string{}}
	for _, s := range st {
		r.statuses[s.id] = models.PlaybookRunCompleted
	}
	runStages(st, r.run, r.status, r.warn, r.skip)

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
	runStages(st, r.run, r.status, r.warn, r.skip)

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
	runStages(st, r.run, r.status, r.warn, r.skip)
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
	runStages(st, r.run, r.status, r.warn, r.skip)
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
	runStages(st, r.run, r.status, r.warn, r.skip)
	if len(r.ran) != 1 {
		t.Error("a status the runner never writes must not be treated as success")
	}
}

func TestNoStagesIsNotAFailure(t *testing.T) {
	r := &recorder{statuses: map[uuid.UUID]string{}}
	runStages(nil, r.run, r.status, r.warn, r.skip)
	if len(r.ran) != 0 || r.warns != 0 {
		t.Error("an empty sequence should do nothing quietly")
	}
}

// A wave that never runs must not be left looking like one that is about to.
//
// Every wave's run row is created before the sequence starts, so when a wave fails and
// the rest are skipped, those rows stay at "pending" unless something closes them. On
// the history screen that is indistinguishable from a run still to come: an operator
// sees one failed wave and one apparently still on its way, for a sequence that stopped
// minutes ago. Observed on a live run — wave 1 failed, wave 2 sat at pending.
func TestSkippedWavesAreClosedOutWithAReason(t *testing.T) {
	st := stages(3)
	r := &recorder{statuses: map[uuid.UUID]string{
		st[0].id: models.PlaybookRunCompleted,
		st[1].id: models.PlaybookRunFailed,
		st[2].id: models.PlaybookRunCompleted, // never reached
	}}
	runStages(st, r.run, r.status, r.warn, r.skip)

	if len(r.ran) != 2 {
		t.Fatalf("ran %d waves, want 2 — the third must not run after the second failed", len(r.ran))
	}
	if _, ok := r.skips[st[2].id]; !ok {
		t.Fatal("the wave that never ran was left untouched, so its run row stays at " +
			"pending and reads as still to come")
	}
	if r.skips[st[0].id] != "" || r.skips[st[1].id] != "" {
		t.Error("a wave that actually ran was marked skipped")
	}
	// The reason has to name what stopped it, or the row says "interrupted" and
	// nothing else.
	if got := r.skips[st[2].id]; !strings.Contains(got, "wave 2") || !strings.Contains(got, "failed") {
		t.Errorf("the reason does not say which wave stopped this one, or how: %q", got)
	}
}

// The same when the result of a wave cannot be read at all: not knowing is not
// permission to continue, and the later waves still have to be closed out.
func TestUnreadableWaveResultAlsoClosesOutTheRest(t *testing.T) {
	st := stages(3)
	r := &recorder{
		statuses: map[uuid.UUID]string{st[0].id: models.PlaybookRunCompleted},
		errs:     map[uuid.UUID]error{st[1].id: errors.New("database gone")},
	}
	runStages(st, r.run, r.status, r.warn, r.skip)
	if _, ok := r.skips[st[2].id]; !ok {
		t.Error("a wave after an unreadable result was left at pending")
	}
}
