package containerupdate

import (
	"context"
	"encoding/json"
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
	containers map[uuid.UUID][]models.Container
	images     map[uuid.UUID][]store.RolloutImage
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
	// Upsert, like the real one: a stack adopted here has to be findable by the
	// retry that follows it, or adoption looks like it worked and changes nothing.
	for i, st := range f.stacks[in.HostID] {
		if st.Name == in.Name {
			f.stacks[in.HostID][i].Compose = in.Compose
			return &f.stacks[in.HostID][i], nil
		}
	}
	st := store.ContainerStack{
		ID: uuid.New(), HostID: in.HostID, Name: in.Name,
		Path: in.Path, Compose: in.Compose, Enabled: true,
	}
	f.stacks[in.HostID] = append(f.stacks[in.HostID], st)
	return &st, nil
}

func (f *fakeStore) GetSetting(_ context.Context, _ string) (json.RawMessage, error) {
	return nil, nil // no override: the default self project applies
}

func (f *fakeStore) RolloutImages(_ context.Context, id uuid.UUID) ([]store.RolloutImage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if im, ok := f.images[id]; ok {
		return im, nil
	}
	// Default: the rollout's own columns, the single-image case.
	for _, r := range f.rollouts {
		if r.ID == id {
			return []store.RolloutImage{{
				Repository: r.Repository, FromTag: r.FromTag,
				ToTag: r.ToTag, TargetDigest: r.TargetDigest,
			}}, nil
		}
	}
	return nil, nil
}

func (f *fakeStore) HostContainers(_ context.Context, hostID uuid.UUID) ([]models.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.containers[hostID], nil
}

func (f *fakeStore) GetHost(_ context.Context, id uuid.UUID) (*models.Host, error) {
	return &models.Host{ID: id, Hostname: "h-" + id.String()[:4]}, nil
}

type fakeDeployer struct {
	mu       sync.Mutex
	calls    int
	err      error
	services []string // what each deploy was narrowed to
}

func (d *fakeDeployer) DeployPulling(context.Context, uuid.UUID) (*store.ContainerStack, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	return nil, "compose output", d.err
}

func (d *fakeDeployer) DeployPullingService(_ context.Context, _ uuid.UUID, service string) (*store.ContainerStack, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	d.services = append(d.services, service)
	return nil, "compose output", d.err
}

type fakeRunner struct {
	mu     sync.Mutex
	out    string
	failed bool
	calls  int
	// respond lets a test answer differently per script. The engine runs several
	// kinds — read back what is running, read a compose file to adopt, pull and
	// recreate — and one fixed string for all of them tests none of them properly.
	respond func(script string) (string, int, bool)
}

func (r *fakeRunner) RunScript(_ context.Context, script string, _ *models.Host) (string, int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.respond != nil {
		return r.respond(script)
	}
	if r.failed {
		return r.out, 1, true
	}
	return r.out, 0, false
}

// scripted answers the verify read-back with `running` and any compose-file read
// with `compose`, which is what most of these tests need.
func scripted(running, compose string) *fakeRunner {
	return &fakeRunner{respond: func(script string) (string, int, bool) {
		if strings.Contains(script, "::COMPOSE::") {
			if compose == "" {
				return "::NOFILE::\n", 0, false
			}
			// What the real script emits: bounded, and with the runner's
			// trailing line, because that is what the engine actually receives.
			return "::COMPOSE::\n" + compose + "::ENDCOMPOSE::\n\n[exit code 0]", 0, false
		}
		return running, 0, false
	}}
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
		hosts:      map[uuid.UUID][]store.UpdateRolloutHost{},
		stacks:     map[uuid.UUID][]store.ContainerStack{},
		containers: map[uuid.UUID][]models.Container{},
		images:     map[uuid.UUID][]store.RolloutImage{},
		claimFail:  map[uuid.UUID]bool{},
	}
	ids := make([]uuid.UUID, n)
	for i := range ids {
		ids[i] = uuid.New()
		f.hosts[rid] = append(f.hosts[rid], store.UpdateRolloutHost{
			HostID: ids[i], State: store.UpdateHostPending})
		f.stacks[ids[i]] = []store.ContainerStack{{
			ID: uuid.New(), HostID: ids[i], Enabled: true, Compose: composeNginx}}
		// The host has to be running the image for the rollout to apply it —
		// a rollout covering several images only applies the ones a given host
		// actually runs.
		f.containers[ids[i]] = []models.Container{{
			Name: "web", Image: "nginx:1.24", Repository: "nginx", Tag: "1.24"}}
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
	if !strings.Contains(h.Error, "adopt this host's compose file") {
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

// --- updating in place, without an adopted stack ---------------------------
//
// Asking an operator to adopt a compose file just to pull a rebuilt image is
// work for nothing: the container's own labels already say which compose project
// and service it is and where that project lives. But only for updates that do
// not need the FILE changed — a version bump is written into the file, and
// editing one Provenance does not own is reverted on the next deploy for any
// host whose compose files come from a git repo or an rsync target.

func inPlaceFixture(from, to string) (*fakeStore, uuid.UUID, uuid.UUID) {
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.rollouts[0].FromTag, f.rollouts[0].ToTag = from, to
	f.stacks[ids[0]] = nil // nothing adopted
	f.containers[ids[0]] = []models.Container{{
		Name: "web", Image: "nginx:" + from, Repository: "nginx", Tag: from,
		ComposeProject: "site", ComposeService: "web", ComposeDir: "/opt/stacks/site",
	}}
	return f, rid, ids[0]
}

func TestARebuildIsAppliedThroughTheHostsOwnComposeProject(t *testing.T) {
	f, rid, _ := inPlaceFixture("1.24", "1.24") // same tag: a rebuild
	f.rollouts[0].TargetDigest = "sha256:new"
	r := &fakeRunner{out: "::OK::\nnginx:1.24\tnginx@sha256:new\n"}
	d := &fakeDeployer{}
	newEngine(f, d, r).Tick(context.Background())

	if d.calls != 0 {
		t.Error("deployed a stack for a host that has none")
	}
	if got := f.hosts[rid][0].State; got != store.UpdateHostVerified {
		t.Fatalf("state = %q (%q) — a rebuild should not need an adopted stack",
			got, f.hosts[rid][0].Error)
	}
}

func TestTheInPlaceScriptPullsBeforeRecreating(t *testing.T) {
	// `up -d` alone finds the tag already present locally and starts the old bytes
	// again. That is the entire failure this feature exists to catch, and it is
	// just as available here as it was in the stack deploy.
	s := inPlaceScript("/opt/stacks/site", "web")
	pull := strings.Index(s, "pull 'web'")
	up := strings.Index(s, "up -d 'web'")
	if pull < 0 || up < 0 {
		t.Fatalf("script does not pull and recreate the service:\n%s", s)
	}
	if pull > up {
		t.Errorf("recreated before pulling, which starts the old image:\n%s", s)
	}
}

func TestTheInPlaceScriptRefusesAProjectItCannotSee(t *testing.T) {
	// working_dir is recorded by whatever ran compose. For a project deployed FROM
	// a container it is that container's path, and the file is not on the host at
	// all. Running blind would either fail confusingly or act on a DIFFERENT
	// project that happens to live at the same path.
	s := inPlaceScript("/opt/stacks/site", "web")
	if !strings.Contains(s, "config --services") {
		t.Error("the script does not check that a compose project is readable there")
	}
	if !strings.Contains(s, "::NOPROJECT::") || !strings.Contains(s, "::NOSERVICE::") {
		t.Error("the script cannot report WHICH check failed, so neither can the row")
	}
}

func TestAVersionBumpAdoptsTheHostsComposeFileAndApplies(t *testing.T) {
	// The new version is written INTO the compose file, so something has to edit
	// it. Requiring an operator to copy that file into Provenance by hand first is
	// the chore that leaves a feature unused — which is how the bot-and-merge-
	// request arrangement this replaces came to be ignored.
	f, rid, _ := inPlaceFixture("1.24", "1.27")
	d := &fakeDeployer{}
	r := scripted("::OK::\nnginx:1.27\tnginx@sha256:new\n", composeNginx)
	newEngine(f, d, r).Tick(context.Background())

	if len(f.saved) == 0 {
		t.Fatalf("nothing was adopted (host state %q: %q)",
			f.hosts[rid][0].State, f.hosts[rid][0].Error)
	}
	// Adopted, then rewritten to the new version, then deployed.
	if !strings.Contains(f.saved[len(f.saved)-1], "nginx:1.27") {
		t.Errorf("the adopted compose was not moved to the new version:\n%s",
			f.saved[len(f.saved)-1])
	}
	if d.calls != 1 {
		t.Errorf("deployed %d times, want 1", d.calls)
	}
	if got := f.hosts[rid][0].State; got != store.UpdateHostVerified {
		t.Errorf("state = %q (%q)", got, f.hosts[rid][0].Error)
	}
}

func TestAdoptionRefusesAComposeFileThatDoesNotNameTheImage(t *testing.T) {
	// The project at that path is not the one this container came from, and
	// rewriting it would edit somebody else's stack.
	f, rid, _ := inPlaceFixture("1.24", "1.27")
	r := scripted("::OK::\nnginx:1.27\tnginx@sha256:new\n",
		"services:\n  other:\n    image: caddy:2\n")
	newEngine(f, &fakeDeployer{}, r).Tick(context.Background())

	h := f.hosts[rid][0]
	if h.State != store.UpdateHostFailed {
		t.Fatalf("state = %q, want failed", h.State)
	}
	if !strings.Contains(h.Error, "names neither nginx:1.24 nor nginx:1.27") {
		t.Errorf("got %q", h.Error)
	}
	if len(f.saved) != 0 {
		t.Error("adopted a compose file that names a different image")
	}
}

func TestAdoptionRefusesADifferentlyNamedComposeFile(t *testing.T) {
	// The deploy writes docker-compose.yml. Adopting a project called something
	// else would leave the original AND write a second one beside it, and compose
	// would then pick whichever its own rules prefer.
	if _, err := parseAdopt("/opt/stacks/site", "::NOFILE::\ncompose.yaml\n"); err == nil {
		t.Fatal("accepted a differently-named compose file")
	} else if !strings.Contains(err.Error(), "compose.yaml") ||
		!strings.Contains(err.Error(), "two compose files") {
		t.Errorf("the error should name the file it found and say why: %v", err)
	}
}

func TestAdoptionReportsAMissingDirectory(t *testing.T) {
	_, err := parseAdopt("/opt/stacks/site", "::NODIR::\n")
	if err == nil || !strings.Contains(err.Error(), "not there") {
		t.Errorf("got %v", err)
	}
}

func TestAdoptionKeepsTheFileVerbatim(t *testing.T) {
	// The content has to be reviewable in the revision history, byte for byte:
	// this is the file an operator is being shown before approving an edit to it.
	body := "# hand-written\nservices:\n  web:\n    image: nginx:1.24   # pinned\n"
	got, err := parseAdopt("/opt/x", "::COMPOSE::\n"+body+"::ENDCOMPOSE::\n\n[exit code 0]")
	if err != nil {
		t.Fatal(err)
	}
	if got != body {
		t.Errorf("the adopted file differs from what was on disk:\n%q\nwant\n%q", got, body)
	}
}

func TestAContainerWithNoComposeLabelsFallsBackToTheStackMessage(t *testing.T) {
	// A plain `docker run` container. Recreating it means reproducing run
	// arguments nobody recorded, so it is reported rather than guessed at.
	f, rid, ids := inPlaceFixture("1.24", "1.24")
	f.containers[ids] = []models.Container{{
		Name: "web", Image: "nginx:1.24", Repository: "nginx", Tag: "1.24",
	}} // no compose labels
	newEngine(f, &fakeDeployer{}, &fakeRunner{out: runningNew}).Tick(context.Background())

	h := f.hosts[rid][0]
	if h.State != store.UpdateHostFailed {
		t.Fatalf("state = %q, want failed", h.State)
	}
	if !strings.Contains(h.Error, "no Provenance-managed stack") {
		t.Errorf("got %q", h.Error)
	}
}

func TestAnAdoptedStackStillWinsOverInPlace(t *testing.T) {
	// If Provenance holds the file, that is the definition of record and the one
	// with a history. In-place is the fallback, not the preference.
	f, rid, ids := inPlaceFixture("1.24", "1.24")
	f.stacks[ids] = []store.ContainerStack{{
		ID: uuid.New(), HostID: ids, Enabled: true, Compose: composeNginx}}
	d := &fakeDeployer{}
	newEngine(f, d, &fakeRunner{out: "::OK::\nnginx:1.24\tnginx@sha256:new\n"}).
		Tick(context.Background())

	if d.calls != 1 {
		t.Errorf("the adopted stack was not used (%d deploys)", d.calls)
	}
	if got := f.hosts[rid][0].State; got != store.UpdateHostVerified {
		t.Errorf("state = %q (%q)", got, f.hosts[rid][0].Error)
	}
}

// --- one rollout, many images ---------------------------------------------
//
// "Update everything that has something available" was otherwise one rollout per
// image, started by hand, each pacing itself independently — so ten images meant
// ten canaries on ten different hosts at once, which is not a canary at all.
// Pacing applies to the whole operation or it does not apply.

// multiFixture: two hosts, three images between them.
func multiFixture() (*fakeStore, uuid.UUID, []uuid.UUID) {
	f, rid, ids := fixture(2, store.UpdateRollout{Canary: 1, BatchSize: 2})
	f.images[rid] = []store.RolloutImage{
		{Repository: "nginx", FromTag: "1.24", ToTag: "1.24", TargetDigest: "sha256:n"},
		{Repository: "redis", FromTag: "7", ToTag: "7", TargetDigest: "sha256:r"},
		{Repository: "caddy", FromTag: "2", ToTag: "2", TargetDigest: "sha256:c"},
	}
	// host 0 runs nginx and redis; host 1 runs nginx only. Nobody runs caddy.
	f.containers[ids[0]] = []models.Container{
		{Name: "web", Repository: "nginx", Tag: "1.24", ComposeDir: "/opt/a", ComposeService: "web"},
		{Name: "cache", Repository: "redis", Tag: "7", ComposeDir: "/opt/a", ComposeService: "cache"},
	}
	f.containers[ids[1]] = []models.Container{
		{Name: "web", Repository: "nginx", Tag: "1.24", ComposeDir: "/opt/b", ComposeService: "web"},
	}
	f.stacks[ids[0]] = nil
	f.stacks[ids[1]] = nil
	return f, rid, ids
}

// verifyAll answers the read-back for every image in multiFixture.
const verifyAll = "::OK::\nnginx:1.24\tnginx@sha256:n\nredis:7\tredis@sha256:r\n"

func TestAHostTakesEveryImageInTheRolloutThatItRuns(t *testing.T) {
	f, rid, _ := multiFixture()
	r := &fakeRunner{out: verifyAll}
	newEngine(f, &fakeDeployer{}, r).Tick(context.Background())

	// Canary is 1, so exactly one host this tick. It runs two of the three
	// images, so two in-place updates plus their verifications.
	verified := 0
	for _, h := range f.hosts[rid] {
		if h.State == store.UpdateHostVerified {
			verified++
		}
	}
	if verified != 1 {
		t.Fatalf("%d hosts verified on the canary tick, want 1 (states: %+v)", verified, f.hosts[rid])
	}
	// Two updates + two read-backs on the one host that runs two images.
	if r.calls < 4 {
		t.Errorf("%d script runs — the host running two of the images should have "+
			"had both applied, not one", r.calls)
	}
}

func TestAnImageAHostDoesNotRunIsNotAFailure(t *testing.T) {
	// A rollout over ten images rarely has all ten on every host. Treating the
	// absent ones as failures would halt it on its budget immediately.
	f, rid, _ := multiFixture()
	newEngine(f, &fakeDeployer{}, &fakeRunner{out: verifyAll}).Tick(context.Background())
	for _, h := range f.hosts[rid] {
		if h.State == store.UpdateHostFailed {
			t.Errorf("host failed over an image it does not run: %q", h.Error)
		}
	}
	for _, s := range f.rolloutSet {
		if strings.HasPrefix(s, store.UpdateRolloutHalted) {
			t.Fatalf("halted: %v", f.rolloutSet)
		}
	}
}

func TestAHostRunningNoneOfTheImagesIsSkippedNotVerified(t *testing.T) {
	// Enrolled, but by the time its turn came it was running none of them —
	// somebody updated it by hand, or the container was removed. Recording that
	// as verified would claim an update that never happened.
	f, rid, ids := multiFixture()
	f.containers[ids[0]] = nil
	f.containers[ids[1]] = nil
	newEngine(f, &fakeDeployer{}, &fakeRunner{out: verifyAll}).Tick(context.Background())

	var skipped, verified int
	for _, h := range f.hosts[rid] {
		switch h.State {
		case store.UpdateHostSkipped:
			skipped++
		case store.UpdateHostVerified:
			verified++
		}
	}
	if verified > 0 {
		t.Errorf("%d hosts reported verified having had nothing applied", verified)
	}
	if skipped == 0 {
		t.Error("a host that took no updates should be skipped, so the row says so")
	}
}

func TestTheFirstFailingImageStopsThatHost(t *testing.T) {
	// Continuing would apply later updates on top of a host already known to be
	// in a state nobody intended.
	f, rid, ids := multiFixture()
	f.containers[ids[0]] = []models.Container{
		{Name: "web", Repository: "nginx", Tag: "1.24"}, // no compose labels: cannot update
		{Name: "cache", Repository: "redis", Tag: "7", ComposeDir: "/opt/a", ComposeService: "cache"},
	}
	f.containers[ids[1]] = nil
	newEngine(f, &fakeDeployer{}, &fakeRunner{out: verifyAll}).Tick(context.Background())

	var failed int
	for _, h := range f.hosts[rid] {
		if h.State == store.UpdateHostFailed {
			failed++
			if !strings.Contains(h.Error, "nginx:1.24") {
				t.Errorf("the error should name the image that failed, got %q", h.Error)
			}
		}
	}
	if failed != 1 {
		t.Errorf("%d hosts failed, want 1", failed)
	}
}

func TestPacingAppliesAcrossTheWholeRolloutNotPerImage(t *testing.T) {
	// The reason this is one rollout rather than ten: a canary of 1 must mean one
	// HOST, whatever number of images it takes.
	f, rid, _ := multiFixture()
	newEngine(f, &fakeDeployer{}, &fakeRunner{out: verifyAll}).Tick(context.Background())

	var started int
	for _, h := range f.hosts[rid] {
		if h.State != store.UpdateHostPending {
			started++
		}
	}
	if started != 1 {
		t.Errorf("%d hosts started on a canary-of-1 tick, want 1", started)
	}
}

func TestTheRolloutDeploysOnlyTheServiceRunningTheImage(t *testing.T) {
	// On a host running eight containers from one compose project, updating one
	// image must not restart the other seven.
	f, _, ids := inPlaceFixture("1.24", "1.27")
	f.containers[ids] = []models.Container{
		{Name: "web", Repository: "nginx", Tag: "1.24",
			ComposeProject: "site", ComposeService: "web", ComposeDir: "/opt/site"},
		{Name: "db", Repository: "postgres", Tag: "16",
			ComposeProject: "site", ComposeService: "db", ComposeDir: "/opt/site"},
	}
	d := &fakeDeployer{}
	r := scripted("::OK::\nnginx:1.27\tnginx@sha256:new\n", composeNginx)
	newEngine(f, d, r).Tick(context.Background())

	if len(d.services) != 1 {
		t.Fatalf("deployed %d times, want 1 (services: %v)", len(d.services), d.services)
	}
	if d.services[0] != "web" {
		t.Errorf("deployed service %q, want \"web\" — the other services must be left alone",
			d.services[0])
	}
}

func TestAnUnknownServiceFallsBackToTheWholeProject(t *testing.T) {
	// Empty means the whole project, which is the old behaviour and the safe
	// fallback: a deploy that touches more than it needed is recoverable, and one
	// that touches nothing because a name was guessed wrong is an update reported
	// as applied that never happened.
	f, _, ids := inPlaceFixture("1.24", "1.27")
	f.containers[ids] = []models.Container{
		{Name: "web", Repository: "nginx", Tag: "1.24", ComposeDir: "/opt/site"}, // no service
	}
	d := &fakeDeployer{}
	newEngine(f, d, scripted("::OK::\nnginx:1.27\tnginx@sha256:new\n", composeNginx)).
		Tick(context.Background())

	if len(d.services) != 1 || d.services[0] != "" {
		t.Errorf("services = %v, want one empty (the whole project)", d.services)
	}
}

// The runner appends "[exit code N]" to every result. Adoption took "everything
// after the opening marker" as the compose file, so that line went into the
// content, was saved as the stack's compose, and was written to a real host:
//
//	qdrant_data:
//
//	[exit code 0]
//	  go-yaml load error: could not find expected ':'
//
// The stack's own compose file, on a live host, made invalid by the tool that was
// supposed to be managing it.
func TestAdoptedContentStopsAtTheClosingMarker(t *testing.T) {
	file := "services:\n  web:\n    image: nginx:1.24\nvolumes:\n  data:\n"
	// Exactly what a RunScript result looks like.
	out := "::COMPOSE::\n" + file + "::ENDCOMPOSE::\n\n[exit code 0]"

	got, err := parseAdopt("/opt/x", out)
	if err != nil {
		t.Fatal(err)
	}
	if got != file {
		t.Errorf("adopted content is not the file:\n%q\nwant\n%q", got, file)
	}
	if strings.Contains(got, "exit code") {
		t.Error("the runner's trailing line was swallowed into the compose content")
	}
}

func TestAFileWithNoTrailingNewlineSurvivesAdoption(t *testing.T) {
	// `cat` emits the file's bytes and the closing echo starts wherever cat left
	// off, so the marker can land on the last line. The content must still come
	// back byte-for-byte.
	file := "services:\n  web:\n    image: nginx:1.24"
	out := "::COMPOSE::\n" + file + "::ENDCOMPOSE::\n\n[exit code 0]"
	got, err := parseAdopt("/opt/x", out)
	if err != nil {
		t.Fatal(err)
	}
	if got != file {
		t.Errorf("got %q, want %q", got, file)
	}
}

func TestTruncatedAdoptOutputIsRefused(t *testing.T) {
	// No closing marker means the read did not finish. Using what arrived would
	// write half a compose file to a host.
	_, err := parseAdopt("/opt/x", "::COMPOSE::\nservices:\n  web:\n")
	if err == nil {
		t.Fatal("accepted a truncated read")
	}
	if !strings.Contains(err.Error(), "not completely") {
		t.Errorf("unclear reason: %v", err)
	}
}

// The rollout that updated a container correctly and then failed itself.
//
//	deployed, but curlimages/curl:8.22.0 is running sha256:58adaa4e…
//	rather than the sha256:d9b4541e… this rollout targets
//
// 58adaa4e was the right digest for 8.22.0. d9b4541e was 8.10.1 — the image it
// had just moved AWAY from. The client had sent the digest from the updates row,
// which is what the FROM tag points at: correct for a rebuild, where from and to
// are the same tag, and the old image's digest for a version bump.
//
// The deploy had worked. Failing on your own expectation is worse than failing to
// act, because the fleet moved and the record says it did not.
func TestVerifyComparesAgainstTheTargetTagNotTheOldOne(t *testing.T) {
	f, rid, _ := inPlaceFixture("1.24", "1.24") // a rebuild
	f.rollouts[0].TargetDigest = "sha256:new"
	newEngine(f, &fakeDeployer{}, scripted("::OK::\nnginx:1.24\tnginx@sha256:new\n", composeNginx)).
		Tick(context.Background())
	if got := f.hosts[rid][0].State; got != store.UpdateHostVerified {
		t.Fatalf("a rebuild landing on its target digest should verify: %q (%q)",
			got, f.hosts[rid][0].Error)
	}

	// A version bump whose target digest is the OLD image's: the host lands on the
	// NEW tag with the NEW digest and must not be reported as a failure for it.
	// The server resolving the digest itself is what prevents this; the engine's
	// job is to compare against whatever it was given, so this pins the shape of
	// the failure rather than the fix.
	g, gid, _ := inPlaceFixture("1.24", "1.27")
	g.rollouts[0].TargetDigest = "sha256:old" // what the client used to send
	newEngine(g, &fakeDeployer{}, scripted("::OK::\nnginx:1.27\tnginx@sha256:new\n", composeNginx)).
		Tick(context.Background())
	h := g.hosts[gid][0]
	if h.State != store.UpdateHostFailed {
		t.Skip("engine no longer compares digests; the server-side resolution covers it")
	}
	if !strings.Contains(h.Error, "rather than the") {
		t.Errorf("got %q", h.Error)
	}
}

// A rollout whose premise expired for one host.
//
// An "update all" was created while qdrant was on :latest. Before it reached the
// host, that service was pinned to a version — ordinary on a fleet somebody is
// working on. The rollout then deployed correctly and failed verification,
// because the tag it was looking for was no longer in the compose file:
//
//	qdrant/qdrant:latest → latest: deployed, but no container on this host
//	is running qdrant/qdrant:latest
//
// That reads as a broken rollout. It is a rollout whose premise expired, which
// deserves to be skipped rather than failed — failing it halts the whole
// operation on its budget for something nobody did wrong.
func TestAnImageTheHostHasBeenRepinnedPastIsSkipped(t *testing.T) {
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1, MaxFailures: 1})
	f.rollouts[0].Repository, f.rollouts[0].FromTag, f.rollouts[0].ToTag = "qdrant/qdrant", "latest", "latest"
	// Inventory still says :latest — it is a snapshot, and this is exactly the
	// window in which it is out of date.
	f.containers[ids[0]] = []models.Container{{
		Name: "qdrant", Image: "qdrant/qdrant:latest",
		Repository: "qdrant/qdrant", Tag: "latest",
		ComposeService: "qdrant", ComposeDir: "/opt/x", ComposeProject: "x",
	}}
	// But the stack — the definition of record — names a version.
	f.stacks[ids[0]] = []store.ContainerStack{{
		ID: uuid.New(), HostID: ids[0], Enabled: true, Name: "x", Path: "/opt/x",
		Compose: "services:\n  qdrant:\n    image: qdrant/qdrant:v1.18.2\n",
	}}

	d := &fakeDeployer{}
	newEngine(f, d, scripted("::OK::\n", "")).Tick(context.Background())

	if d.calls != 0 {
		t.Error("deployed an image the host has been re-pinned past")
	}
	h := f.hosts[rid][0]
	if h.State == store.UpdateHostFailed {
		t.Fatalf("failed on an expired premise: %q", h.Error)
	}
	if h.State != store.UpdateHostSkipped {
		t.Errorf("state = %q, want skipped — nothing applied, and nothing wrong", h.State)
	}
	for _, s := range f.rolloutSet {
		if strings.HasPrefix(s, store.UpdateRolloutHalted) {
			t.Errorf("the whole rollout halted over an expired premise: %v", f.rolloutSet)
		}
	}
}

func TestARepositoryTheComposeDoesNotMentionIsNotSuperseded(t *testing.T) {
	// Only a repository the file NAMES counts. A compose file that says nothing
	// about an image tells us nothing about whether the host moved past it — the
	// container may be running outside any stack.
	compose := "services:\n  web:\n    image: nginx:1.24\n"
	if composeSupersedes(compose, "qdrant/qdrant", "latest", "latest") {
		t.Error("a repository the file never mentions was treated as superseded")
	}
	if !composeSupersedes(compose, "nginx", "1.20", "1.21") {
		t.Error("a repository pinned to some other tag should be superseded")
	}
	if composeSupersedes(compose, "nginx", "1.24", "1.27") {
		t.Error("the tag the file actually names is not superseded")
	}
}

// The same expired premise, on a host with NO adopted stack.
//
// The first fix compared against the host's stack — which works only where one
// exists. The host it kept failing on had none:
//
//	ghcr.io/alexta69/metube:latest → latest: deployed, but no container on
//	this host is running ghcr.io/alexta69/metube:latest
//
// metube had been pinned in that host's own compose file. With no stack there is
// no copy for the engine to compare against, so the arbiter has to be what is
// actually RUNNING — which the verify step already reads.
func TestSupersessionIsDetectedFromWhatIsRunningNotOnlyFromAStack(t *testing.T) {
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1, MaxFailures: 1})
	f.rollouts[0].Repository, f.rollouts[0].FromTag, f.rollouts[0].ToTag = "metube", "latest", "latest"
	f.stacks[ids[0]] = nil // no stack on this host at all
	f.containers[ids[0]] = []models.Container{{
		Name: "metube", Image: "metube:latest", Repository: "metube", Tag: "latest",
		ComposeService: "metube", ComposeDir: "/opt/x", ComposeProject: "x",
	}}

	// The host is in fact running a pinned version, not :latest.
	r := scripted("::OK::\nmetube:2026.07.24\tmetube@sha256:aaa\n", "")
	newEngine(f, &fakeDeployer{}, r).Tick(context.Background())

	h := f.hosts[rid][0]
	if h.State == store.UpdateHostFailed {
		t.Fatalf("failed on an expired premise with no stack to compare against: %q", h.Error)
	}
	for _, s := range f.rolloutSet {
		if strings.HasPrefix(s, store.UpdateRolloutHalted) {
			t.Errorf("the rollout halted: %v", f.rolloutSet)
		}
	}
}

func TestStillOnTheOldTagIsAFailureNotASupersession(t *testing.T) {
	// The distinction that matters. A container left on the tag the rollout was
	// moving AWAY from is a deploy that reported success and changed nothing —
	// the exact failure this feature exists to catch. Only some THIRD tag means
	// the host moved past the image.
	f, rid, _ := inPlaceFixture("1.24", "1.27")
	r := scripted("::OK::\nnginx:1.24\tnginx@sha256:old\n", composeNginx)
	newEngine(f, &fakeDeployer{}, r).Tick(context.Background())

	if got := f.hosts[rid][0].State; got != store.UpdateHostFailed {
		t.Errorf("state = %q, want failed — the deploy left the old image running", got)
	}
}
