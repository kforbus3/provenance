package containerupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// --- fakes -------------------------------------------------------------------

type fakeStore struct {
	// A real store is a connection pool, safe for concurrent use; a batch of
	// hosts is applied concurrently, so the fake has to be safe too or -race
	// reports the fake rather than the engine.
	mu         sync.Mutex
	rollouts   []store.UpdateRollout
	hosts      map[uuid.UUID][]store.UpdateRolloutHost
	stacks     map[uuid.UUID][]store.ContainerStack
	saved      []string // compose bodies written
	stateCalls []string // "host:state"
	rolloutSet []string // "rollout:state:reason"
	canaryAt   *time.Time
	claimFail  map[uuid.UUID]bool
}

func (f *fakeStore) ActiveUpdateRollouts(context.Context) ([]store.UpdateRollout, error) {
	return f.rollouts, nil
}

func (f *fakeStore) UpdateRolloutHosts(_ context.Context, id uuid.UUID) ([]store.UpdateRolloutHost, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hosts[id], nil
}

func (f *fakeStore) ClaimUpdateRolloutHost(_ context.Context, rollout, host uuid.UUID) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimFail[host] {
		return false, nil
	}
	for i, h := range f.hosts[rollout] {
		if h.HostID == host && h.State == store.UpdateHostPending {
			f.hosts[rollout][i].State = store.UpdateHostApplying
			f.hosts[rollout][i].Attempts++
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeStore) SetUpdateRolloutHostState(_ context.Context, rollout, host uuid.UUID, state, errMsg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stateCalls = append(f.stateCalls, host.String()[:8]+":"+state)
	for i, h := range f.hosts[rollout] {
		if h.HostID == host {
			f.hosts[rollout][i].State = state
			f.hosts[rollout][i].Error = errMsg
		}
	}
	return nil
}

func (f *fakeStore) SetUpdateRolloutState(_ context.Context, id uuid.UUID, state, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rolloutSet = append(f.rolloutSet, fmt.Sprintf("%s:%s", state, reason))
	return nil
}

func (f *fakeStore) StampUpdateRolloutCanaryDone(_ context.Context, _ uuid.UUID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.canaryAt == nil {
		f.canaryAt = &at
	}
	return nil
}

func (f *fakeStore) ListStacks(_ context.Context, hostID *uuid.UUID) ([]store.ContainerStack, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if hostID == nil {
		return nil, nil
	}
	return f.stacks[*hostID], nil
}

func (f *fakeStore) UpsertStack(_ context.Context, in store.StackInput) (*store.ContainerStack, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saved = append(f.saved, in.Compose)
	return &store.ContainerStack{HostID: in.HostID, Compose: in.Compose}, nil
}

func (f *fakeStore) GetHost(_ context.Context, id uuid.UUID) (*models.Host, error) {
	return &models.Host{ID: id, Hostname: "h-" + id.String()[:4]}, nil
}

type fakeDeployer struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (d *fakeDeployer) DeployPulling(context.Context, uuid.UUID) (*store.ContainerStack, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	return nil, "compose output", d.err
}

type fakeRunner struct {
	mu     sync.Mutex
	out    string
	failed bool
	calls  int
}

func (r *fakeRunner) RunScript(context.Context, string, *models.Host) (string, int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.failed {
		return r.out, 1, true
	}
	return r.out, 0, false
}

// --- helpers -----------------------------------------------------------------

const composeNginx = "services:\n  web:\n    image: nginx:1.24\n"

func newEngine(f *fakeStore, d *fakeDeployer, r *fakeRunner) *Engine {
	e := New(f, d, r, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.now = func() time.Time { return time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC) }
	return e
}

// fixture builds a rollout over n hosts, each with a managed nginx stack.
func fixture(n int, strategy store.UpdateRollout) (*fakeStore, uuid.UUID, []uuid.UUID) {
	rid := uuid.New()
	r := strategy
	r.ID = rid
	r.Repository, r.FromTag, r.ToTag = "nginx", "1.24", "1.27"
	r.State = store.UpdateRolloutRunning

	f := &fakeStore{
		hosts:     map[uuid.UUID][]store.UpdateRolloutHost{},
		stacks:    map[uuid.UUID][]store.ContainerStack{},
		claimFail: map[uuid.UUID]bool{},
	}
	ids := make([]uuid.UUID, n)
	for i := range ids {
		ids[i] = uuid.New()
		f.hosts[rid] = append(f.hosts[rid], store.UpdateRolloutHost{
			HostID: ids[i], State: store.UpdateHostPending})
		f.stacks[ids[i]] = []store.ContainerStack{{
			ID: uuid.New(), HostID: ids[i], Enabled: true, Compose: composeNginx}}
	}
	f.rollouts = []store.UpdateRollout{r}
	return f, rid, ids
}

// runningNew is what the verification read-back looks like on a host that took
// the update.
const runningNew = "::OK::\nnginx:1.27\tnginx@sha256:new\n"

// --- tests -------------------------------------------------------------------

func TestTheCanaryGoesFirstAndAlone(t *testing.T) {
	f, rid, _ := fixture(5, store.UpdateRollout{Canary: 1, BatchSize: 5, SoakSeconds: 900})
	d := &fakeDeployer{}
	newEngine(f, d, &fakeRunner{out: runningNew}).Tick(context.Background())

	if d.calls != 1 {
		t.Fatalf("deployed to %d hosts on the first tick, want 1 (the canary)", d.calls)
	}
	var verified int
	for _, h := range f.hosts[rid] {
		if h.State == store.UpdateHostVerified {
			verified++
		}
	}
	if verified != 1 {
		t.Errorf("%d hosts verified, want 1", verified)
	}
}

func TestTheSoakKeepsTheFleetBehindTheCanary(t *testing.T) {
	f, _, _ := fixture(5, store.UpdateRollout{Canary: 1, BatchSize: 5, SoakSeconds: 900})
	d := &fakeDeployer{}
	e := newEngine(f, d, &fakeRunner{out: runningNew})

	start := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	e.Tick(context.Background()) // the canary starts and verifies
	if d.calls != 1 {
		t.Fatalf("first tick deployed to %d hosts, want 1", d.calls)
	}

	// The canary phase is only STAMPED once a later tick sees it verified, so
	// the second tick is what arms the soak. It must not also start the fleet.
	e.now = func() time.Time { return start.Add(time.Minute) }
	e.Tick(context.Background())
	if f.canaryAt == nil {
		t.Fatal("the canary phase was never stamped, so the soak can never end")
	}
	f.rollouts[0].CanaryDoneAt = f.canaryAt
	if d.calls != 1 {
		t.Errorf("%d hosts started on the tick that armed the soak", d.calls-1)
	}

	// Still inside the soak: an update that breaks a host ten minutes in is
	// still broken, and without this the whole fleet already has it.
	e.now = func() time.Time { return f.canaryAt.Add(5 * time.Minute) }
	e.Tick(context.Background())
	if d.calls != 1 {
		t.Errorf("%d hosts started during the soak", d.calls-1)
	}

	// Past the soak, the rest goes.
	e.now = func() time.Time { return f.canaryAt.Add(20 * time.Minute) }
	e.Tick(context.Background())
	if d.calls != 5 {
		t.Errorf("after the soak %d hosts had been deployed to, want 5", d.calls)
	}
}

func TestTheBatchSizeCapsEachTick(t *testing.T) {
	f, _, _ := fixture(10, store.UpdateRollout{Canary: 0, BatchSize: 3})
	d := &fakeDeployer{}
	newEngine(f, d, &fakeRunner{out: runningNew}).Tick(context.Background())
	if d.calls != 3 {
		t.Errorf("deployed to %d hosts, want 3 (the batch size)", d.calls)
	}
}

func TestTheFailureBudgetHaltsTheRollout(t *testing.T) {
	f, rid, _ := fixture(5, store.UpdateRollout{Canary: 0, BatchSize: 2, MaxFailures: 2})
	d := &fakeDeployer{err: errors.New("deploy failed")}
	e := newEngine(f, d, &fakeRunner{out: runningNew})
	e.Tick(context.Background()) // two hosts start, both fail

	failed := 0
	for _, h := range f.hosts[rid] {
		if h.State == store.UpdateHostFailed {
			failed++
		}
	}
	if failed != 2 {
		t.Fatalf("%d hosts failed, want 2", failed)
	}
	before := d.calls
	e.Tick(context.Background()) // must halt rather than send more
	if d.calls != before {
		t.Errorf("%d more hosts were started under a rollout over its budget", d.calls-before)
	}
	if len(f.rolloutSet) == 0 || !strings.HasPrefix(f.rolloutSet[len(f.rolloutSet)-1], store.UpdateRolloutHalted) {
		t.Errorf("the rollout was not halted: %v", f.rolloutSet)
	}
}

func TestAZeroBudgetMeansUnlimitedNotZeroTolerance(t *testing.T) {
	// Reading `failures > MaxFailures` as the whole rule turns "no limit" into
	// "halt on the first failure", which is the opposite of what an operator who
	// left the field empty asked for.
	f, _, _ := fixture(4, store.UpdateRollout{Canary: 0, BatchSize: 4, MaxFailures: 0})
	d := &fakeDeployer{err: errors.New("nope")}
	e := newEngine(f, d, &fakeRunner{out: runningNew})
	e.Tick(context.Background())
	for _, s := range f.rolloutSet {
		if strings.HasPrefix(s, store.UpdateRolloutHalted) {
			t.Fatalf("halted despite an unlimited budget: %v", f.rolloutSet)
		}
	}
}

func TestADeployThatLeavesTheOldImageRunningIsAFailure(t *testing.T) {
	// The failure this rollout exists to catch. `up -d` exits zero having done
	// nothing when the image is already present locally; counting the exit code
	// would march a no-op across the fleet and report every host as updated.
	f, rid, _ := fixture(3, store.UpdateRollout{Canary: 1, BatchSize: 3})
	d := &fakeDeployer{}
	// The host still reports the OLD tag.
	newEngine(f, d, &fakeRunner{out: "::OK::\nnginx:1.24\tnginx@sha256:old\n"}).
		Tick(context.Background())

	h := f.hosts[rid][0]
	if h.State != store.UpdateHostFailed {
		t.Fatalf("host state = %q, want failed", h.State)
	}
	if !strings.Contains(h.Error, "no container on this host is running nginx:1.27") {
		t.Errorf("the error should say what was expected, got %q", h.Error)
	}
}

func TestARebuildAtTheWrongDigestIsAFailure(t *testing.T) {
	// The host is on the right TAG but the wrong bytes — which is exactly the
	// situation a rebuild rollout was started to fix, so accepting it would mean
	// the rollout reports success for the thing it was meant to change.
	f, rid, _ := fixture(2, store.UpdateRollout{Canary: 1, BatchSize: 2})
	f.rollouts[0].TargetDigest = "sha256:wanted"
	newEngine(f, &fakeDeployer{}, &fakeRunner{out: "::OK::\nnginx:1.27\tnginx@sha256:other\n"}).
		Tick(context.Background())

	h := f.hosts[rid][0]
	if h.State != store.UpdateHostFailed {
		t.Fatalf("state = %q, want failed", h.State)
	}
	if !strings.Contains(h.Error, "rather than the") {
		t.Errorf("got %q", h.Error)
	}
}

func TestTheRightDigestVerifies(t *testing.T) {
	f, rid, _ := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.rollouts[0].TargetDigest = "sha256:wanted"
	newEngine(f, &fakeDeployer{}, &fakeRunner{out: "::OK::\nnginx:1.27\tnginx@sha256:wanted\n"}).
		Tick(context.Background())
	if got := f.hosts[rid][0].State; got != store.UpdateHostVerified {
		t.Errorf("state = %q, want verified (error: %q)", got, f.hosts[rid][0].Error)
	}
}

func TestAHostWithNoManagedStackFailsWithAnActionableReason(t *testing.T) {
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.stacks[ids[0]] = nil // the container is running, but Provenance does not own it
	newEngine(f, &fakeDeployer{}, &fakeRunner{out: runningNew}).Tick(context.Background())

	h := f.hosts[rid][0]
	if h.State != store.UpdateHostFailed {
		t.Fatalf("state = %q, want failed", h.State)
	}
	// "deploy failed" would send an operator to look at docker. The fix is to
	// adopt the compose file, and the message has to say so.
	if !strings.Contains(h.Error, "adopt its compose file") {
		t.Errorf("the error should say what to do about it, got %q", h.Error)
	}
}

func TestTheComposeIsRewrittenBeforeDeploying(t *testing.T) {
	f, _, _ := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	newEngine(f, &fakeDeployer{}, &fakeRunner{out: runningNew}).Tick(context.Background())
	if len(f.saved) != 1 {
		t.Fatalf("saved %d revisions, want 1", len(f.saved))
	}
	if !strings.Contains(f.saved[0], "image: nginx:1.27") {
		t.Errorf("the saved compose was not rewritten:\n%s", f.saved[0])
	}
}

func TestADigestOnlyUpdateWritesNoNewRevision(t *testing.T) {
	// The same tag rebuilt. There is nothing to rewrite, and writing an identical
	// revision would fill the history with entries that record no change while
	// claiming one.
	f, rid, _ := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.rollouts[0].ToTag = "1.24" // same as from
	f.rollouts[0].TargetDigest = "sha256:rebuilt"
	d := &fakeDeployer{}
	newEngine(f, d, &fakeRunner{out: "::OK::\nnginx:1.24\tnginx@sha256:rebuilt\n"}).
		Tick(context.Background())

	if len(f.saved) != 0 {
		t.Errorf("wrote %d revisions for a digest-only update, want 0", len(f.saved))
	}
	if d.calls != 1 {
		t.Errorf("deployed %d times, want 1 — the pull IS the update", d.calls)
	}
	if got := f.hosts[rid][0].State; got != store.UpdateHostVerified {
		t.Errorf("state = %q (%q)", got, f.hosts[rid][0].Error)
	}
}

func TestOutsideTheWindowNothingStarts(t *testing.T) {
	f, _, _ := fixture(3, store.UpdateRollout{Canary: 0, BatchSize: 3})
	start, end := "22:00", "04:00"
	f.rollouts[0].WindowStart, f.rollouts[0].WindowEnd = &start, &end
	d := &fakeDeployer{}
	e := newEngine(f, d, &fakeRunner{out: runningNew}) // clock is 12:00
	e.Tick(context.Background())
	if d.calls != 0 {
		t.Errorf("%d hosts started at noon under a 22:00-04:00 window", d.calls)
	}

	e.now = func() time.Time { return time.Date(2026, 9, 12, 23, 30, 0, 0, time.UTC) }
	e.Tick(context.Background())
	if d.calls != 3 {
		t.Errorf("%d hosts started inside the window, want 3", d.calls)
	}
}

func TestAHostClaimedElsewhereIsNotDeployedTo(t *testing.T) {
	// Two overlapping ticks must not both deploy to one host: for a compose file
	// that means two writers racing on the same path.
	f, _, ids := fixture(2, store.UpdateRollout{Canary: 0, BatchSize: 2})
	f.claimFail[ids[0]] = true
	d := &fakeDeployer{}
	newEngine(f, d, &fakeRunner{out: runningNew}).Tick(context.Background())
	if d.calls != 1 {
		t.Errorf("deployed %d times, want 1 — the claimed host must be skipped", d.calls)
	}
}

func TestARolloutWithNothingLeftCompletes(t *testing.T) {
	f, rid, _ := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	e := newEngine(f, &fakeDeployer{}, &fakeRunner{out: runningNew})
	e.Tick(context.Background()) // the one host verifies
	e.Tick(context.Background()) // nothing pending, nothing flying

	if len(f.rolloutSet) == 0 ||
		!strings.HasPrefix(f.rolloutSet[len(f.rolloutSet)-1], store.UpdateRolloutCompleted) {
		t.Errorf("the rollout did not complete: %v (hosts %+v)", f.rolloutSet, f.hosts[rid])
	}
}

func TestAHostOutOfAttemptsFailsRatherThanLooping(t *testing.T) {
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.hosts[rid][0].Attempts = MaxAttempts
	d := &fakeDeployer{}
	newEngine(f, d, &fakeRunner{out: runningNew}).Tick(context.Background())
	if d.calls != 0 {
		t.Errorf("deployed to a host that was out of attempts")
	}
	if f.hosts[rid][0].State != store.UpdateHostFailed {
		t.Errorf("state = %q, want failed", f.hosts[rid][0].State)
	}
	_ = ids
}

func TestForgivenFailuresDoNotReHaltAResumedRollout(t *testing.T) {
	// Resume marks the failures forgiven. Counting them again re-halts on the
	// very next tick, making resume a button that reports success and does
	// nothing.
	f, rid, _ := fixture(4, store.UpdateRollout{Canary: 0, BatchSize: 1, MaxFailures: 1})
	f.hosts[rid][0].State = store.UpdateHostFailed
	f.hosts[rid][0].Forgiven = true
	d := &fakeDeployer{}
	newEngine(f, d, &fakeRunner{out: runningNew}).Tick(context.Background())

	for _, s := range f.rolloutSet {
		if strings.HasPrefix(s, store.UpdateRolloutHalted) {
			t.Fatalf("re-halted on a forgiven failure: %v", f.rolloutSet)
		}
	}
	if d.calls != 1 {
		t.Errorf("the resumed rollout deployed %d times, want 1", d.calls)
	}
}

func TestAnUnreadableHostIsNotCountedAsVerified(t *testing.T) {
	f, rid, _ := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	newEngine(f, &fakeDeployer{}, &fakeRunner{out: "::NORUNTIME::", failed: false}).
		Tick(context.Background())
	if got := f.hosts[rid][0].State; got != store.UpdateHostFailed {
		t.Errorf("state = %q, want failed — a host that cannot be read back is not verified", got)
	}
}

func TestTheVerifyScriptOnlyMatchesTheTargetRepository(t *testing.T) {
	if got := shellCase("nginx"); got != "'nginx:'*" {
		t.Errorf("shellCase(\"nginx\") = %q, want 'nginx:'*", got)
	}
	if !strings.Contains(verifyScript("nginx"), "'nginx:'*") {
		t.Error("the pattern is not in the generated script")
	}

	// A repository name cannot contain shell metacharacters, so anything that
	// does is not a repository this should match — and a `case` pattern built
	// from it would run on the host. The pattern is what gets interpolated, so
	// that is what must be clean; the surrounding script's own punctuation is
	// not evidence of anything.
	for _, repo := range []string{
		"evil';rm -rf /;'", "a`id`b", "x$(id)y", "p|q", "a&b", "s>t", "q\"r",
	} {
		got := shellCase(repo)
		inner := strings.TrimSuffix(strings.TrimPrefix(got, "'"), ":'*")
		if strings.ContainsAny(inner, "*?[]\\'\"`$();|&<>\n") {
			t.Errorf("shellCase(%q) = %q — metacharacters survived", repo, got)
		}
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, ":'*") {
			t.Errorf("shellCase(%q) = %q — not a quoted tag-wildcard pattern", repo, got)
		}
	}
}
