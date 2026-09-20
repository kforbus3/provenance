package containerupdate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/store"
)

// The message that ended a real rollout, verbatim from the host row that
// recorded it.
const rateLimited = `ghcr.io/linuxserver/faster-whisper:gpu-v3.8.1-ls66 → gpu-v3.8.1-ls67: 09c32a2c2d0b Downloading 6.158MB
1fd3dd5e1b01 Downloading 0B
toomanyrequests: retry-after: 548.005µs, allowed: 44000/minute

[exit code 1]`

// A registry rate limit must not end a rollout.
//
// Production, 2026-09-20: a three-image rollout across two hosts. The first
// host's pull came back asking to be retried in 548 MICROseconds. That was
// recorded as the host's failure; the failure budget was one host; the rollout
// halted; the second host was left pending forever. Nothing was wrong with the
// fleet, the images, or the compose files.
func TestARateLimitLeavesTheHostRetryableRatherThanFailed(t *testing.T) {
	f, rid, _ := fixture(2, store.UpdateRollout{Canary: 1, BatchSize: 5, MaxFailures: 1})
	d := &fakeDeployer{err: errors.New(rateLimited)}
	e := newEngine(f, d, &fakeRunner{out: runningNew})
	e.Tick(context.Background())

	for _, h := range f.hosts[rid] {
		if h.State == store.UpdateHostFailed {
			t.Errorf("a registry rate limit was recorded as a host failure: %s", h.Error)
		}
	}
	for _, s := range f.rolloutSet {
		if strings.HasPrefix(s, store.UpdateRolloutHalted) {
			t.Fatalf("the rollout halted over a rate limit that clears in half a "+
				"millisecond: %v", f.rolloutSet)
		}
	}

	// And it is genuinely retried, not silently dropped: the next tick starts it
	// again.
	before := d.calls
	e.Tick(context.Background())
	if d.calls == before {
		t.Error("the host was left pending but never attempted again")
	}
}

// The retry is bounded. A registry that is actually down must end the host
// rather than being asked forever.
func TestRetriesRunOutAndTheHostFails(t *testing.T) {
	f, rid, _ := fixture(1, store.UpdateRollout{Canary: 0, BatchSize: 1, MaxFailures: 1})
	d := &fakeDeployer{err: errors.New(rateLimited)}
	e := newEngine(f, d, &fakeRunner{out: runningNew})
	for i := 0; i < MaxAttempts+2; i++ {
		e.Tick(context.Background())
	}
	if got := f.hosts[rid][0].State; got != store.UpdateHostFailed {
		t.Errorf("host state is %q after %d ticks, want failed — a transient "+
			"classification that never gives up is an infinite loop", got, MaxAttempts+2)
	}
	if d.calls > MaxAttempts {
		t.Errorf("attempted %d deploys, want at most %d", d.calls, MaxAttempts)
	}
}

// A permanent failure is recorded on the first attempt. Retrying an answer
// produces the same answer later and buries the message under copies of itself.
func TestAPermanentFailureIsNotRetried(t *testing.T) {
	f, rid, _ := fixture(1, store.UpdateRollout{Canary: 0, BatchSize: 1, MaxFailures: 1})
	d := &fakeDeployer{err: errors.New("unauthorized: authentication required")}
	newEngine(f, d, &fakeRunner{out: runningNew}).Tick(context.Background())
	if got := f.hosts[rid][0].State; got != store.UpdateHostFailed {
		t.Errorf("host state is %q, want failed on the first attempt", got)
	}
}

// When a rollout halts, a host that never got a turn must not be left saying
// "pending" — the rollout is never advanced again, so it is waiting for
// something that will not happen. One sat like that in production beside a
// rollout that had already stopped.
func TestAHaltClosesOutTheHostsThatNeverRan(t *testing.T) {
	f, rid, _ := fixture(4, store.UpdateRollout{Canary: 0, BatchSize: 1, MaxFailures: 1})
	d := &fakeDeployer{err: errors.New("manifest unknown: manifest unknown")}
	e := newEngine(f, d, &fakeRunner{out: runningNew})
	e.Tick(context.Background()) // one host runs and fails
	e.Tick(context.Background()) // budget is spent: halt

	var pending, skipped int
	for _, h := range f.hosts[rid] {
		switch h.State {
		case store.UpdateHostPending:
			pending++
		case store.UpdateHostSkipped:
			skipped++
		}
	}
	if pending != 0 {
		t.Errorf("%d host(s) left pending under a halted rollout", pending)
	}
	if skipped != 3 {
		t.Errorf("%d host(s) closed out as skipped, want 3", skipped)
	}
}

// The halt reason has to name the failure.
//
// "1 host(s) failed; the rollout stopped on its own." was the whole message. A
// rollout carrying three images is listed under the name of the first one, so a
// halt caused by faster-whisper was displayed as a llama.cpp failure and the
// operator had to open the host rows to find out otherwise.
func TestTheHaltReasonNamesWhatFailed(t *testing.T) {
	f, _, _ := fixture(2, store.UpdateRollout{Canary: 0, BatchSize: 1, MaxFailures: 1})
	d := &fakeDeployer{err: errors.New("ghcr.io/linuxserver/faster-whisper:gpu-v3.8.1-ls66 → " +
		"gpu-v3.8.1-ls67: manifest unknown")}
	e := newEngine(f, d, &fakeRunner{out: runningNew})
	e.Tick(context.Background())
	e.Tick(context.Background())

	var halt string
	for _, s := range f.rolloutSet {
		if strings.HasPrefix(s, store.UpdateRolloutHalted) {
			halt = s
		}
	}
	if halt == "" {
		t.Fatalf("the rollout did not halt: %v", f.rolloutSet)
	}
	if !strings.Contains(halt, "faster-whisper") {
		t.Errorf("the halt reason does not say what failed: %q", halt)
	}
}

// A rollout that rewrote a compose file, and whose host then put the old file
// back, must take its own revision back too.
//
// Otherwise the two disagree with no way to tell which is right: the host runs
// ls66 from the file the deploy script restored, while the stack record holds
// the ls67 text the rollout wrote. Both look fine on their own. The next deploy
// of that project — for any reason, by anyone — resolves the disagreement by
// applying a version nobody chose.
func TestARevertedHostTakesTheStackRecordWithIt(t *testing.T) {
	f, _, ids := fixture(1, store.UpdateRollout{Canary: 0, BatchSize: 1, MaxFailures: 1})
	before := f.stacks[ids[0]][0].Compose
	d := &fakeDeployer{
		err: errors.New("deploy failed"),
		out: "::PULLFAILED::the images could not be pulled (exit 1)\n" +
			"::REVERTEDTO::docker-compose.yml.last-good\n::REVERTEDREV::11",
	}
	newEngine(f, d, &fakeRunner{out: runningNew}).Tick(context.Background())

	if got := f.stacks[ids[0]][0].Compose; got != before {
		t.Errorf("the host went back but the stack record did not.\nstored: %q\n  host: %q",
			got, before)
	}
	// Through a new revision, so the history still records that the bump was
	// attempted.
	if len(f.saved) < 2 {
		t.Errorf("expected the bump and the revert to be two recorded revisions, got %d", len(f.saved))
	}
}

// The opposite case, which the same code must not break: a deploy that FAILED
// but left the new file in place (it ran, and did not produce the expected
// container) must keep the stack record on the new text. Reverting there would
// create the very disagreement this is meant to prevent.
func TestAFailureThatKeptTheNewFileKeepsTheRecord(t *testing.T) {
	f, _, ids := fixture(1, store.UpdateRollout{Canary: 0, BatchSize: 1, MaxFailures: 1})
	before := f.stacks[ids[0]][0].Compose
	d := &fakeDeployer{err: errors.New("deploy failed"), out: "no markers here"}
	newEngine(f, d, &fakeRunner{out: runningNew}).Tick(context.Background())

	if got := f.stacks[ids[0]][0].Compose; got == before {
		t.Error("the stack record was reverted although the host kept the new compose file")
	}
}
