package containerupdate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/notify"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// The fake's half of the post-rollout watch: an in-memory table with the same
// due/once semantics as the real one.

func (f *fakeStore) CreateRolloutWatches(_ context.Context, rollout, host uuid.UUID,
	images []store.RolloutImage, from time.Time, window time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
next:
	for _, im := range images {
		for _, w := range f.watches {
			if w.RolloutID == rollout && w.HostID == host && w.Repository == im.Repository {
				continue next
			}
		}
		f.watches = append(f.watches, store.RolloutWatch{
			ID: uuid.New(), RolloutID: rollout, HostID: host, Hostname: "h-" + host.String()[:4],
			Repository: im.Repository, ToTag: im.ToTag,
			StartedAt: from, ExpiresAt: from.Add(window), CheckedAt: from,
		})
	}
	return nil
}

func (f *fakeStore) DueRolloutWatches(_ context.Context, now time.Time, every time.Duration) ([]store.RolloutWatch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.RolloutWatch
	for _, w := range f.watches {
		if w.RegressionAt == nil && w.ExpiresAt.After(now) && !w.CheckedAt.After(now.Add(-every)) {
			out = append(out, w)
		}
	}
	return out, nil
}

func (f *fakeStore) SetRolloutWatchChecked(_ context.Context, id uuid.UUID, at time.Time, regression string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.watches {
		if f.watches[i].ID != id {
			continue
		}
		f.watches[i].CheckedAt = at
		if regression != "" && f.watches[i].RegressionAt == nil {
			f.watches[i].Regression = regression
			at := at
			f.watches[i].RegressionAt = &at
		}
	}
	return nil
}

// A verify line with the two log columns the 2026-10-04 incident added.
const whisperTrace = "linuxserver/faster-whisper:gpu-v3.8.1-ls69\twyoming-whisper\trunning\t" +
	"ghcr.io/linuxserver/faster-whisper@sha256:w\thealthy\t0\t6\t" +
	"Traceback (most recent call last):\n"

// The read-back carries how many error traces a container has logged and the
// first of them. Older output without the columns reads as unknown, not zero.
func TestVerifyOutputCarriesErrorTraces(t *testing.T) {
	got := parseVerifyOutput("::OK::\n" + whisperTrace +
		"redis:7\tcache\trunning\tredis@sha256:y,\thealthy\t0\n")
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].traces != 6 || !strings.HasPrefix(got[0].trace, "Traceback") {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].traces != -1 || got[1].trace != "" {
		t.Errorf("second = %+v", got[1])
	}
}

// The verify script reads the logs from the cursor it is given, and from the
// container's own start when it is given none. The pattern is the narrow one:
// crashes, not log lines that happen to say "error".
func TestTheVerifyScriptTailsLogsFromItsCursor(t *testing.T) {
	s := verifyScriptSince("nginx", "2026-10-04T23:39:13Z")
	for _, want := range []string{
		"_since='2026-10-04T23:39:13Z'",
		"logs --since \"$_from\"",
		"{{.State.StartedAt}}",
		"Traceback",
		"^panic: ",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if strings.Contains(logTracePattern, "ERROR") || strings.Contains(logTracePattern, "level=error") {
		t.Errorf("the pattern matches ordinary error lines, which would make the watch unbearable: %s", logTracePattern)
	}
	if !strings.Contains(verifyScript("nginx"), "_since=''") {
		t.Errorf("verifyScript must read from the container's start")
	}
}

// Running, healthy, never restarted, and failing every request: the soak
// re-check now reads the logs, and halts on a container that has been throwing
// tracebacks since it was deployed.
func TestASoakRecheckHaltsOnErrorTraces(t *testing.T) {
	f, rid, ids := fleetFixture(store.UpdateRollout{Canary: 1, BatchSize: 5, SoakSeconds: 300})
	r := &fakeRunner{out: verifyFleet}
	e := newEngine(f, &fakeDeployer{}, r)
	start := time.Date(2026, 10, 4, 19, 39, 0, 0, time.UTC)
	e.now = func() time.Time { return start }
	e.Tick(context.Background())
	e.now = func() time.Time { return start.Add(time.Minute) }
	e.Tick(context.Background())

	r.mu.Lock()
	r.out = "::OK::\nnginx:1.24\tweb\trunning\tnginx@sha256:n\thealthy\t0\t3\tTraceback (most recent call last):\n"
	r.mu.Unlock()
	e.now = func() time.Time { return start.Add(10 * time.Minute) }
	e.Tick(context.Background())

	halted := ""
	for _, s := range f.rolloutSet {
		if strings.Contains(s, store.UpdateRolloutHalted) {
			halted = s
		}
	}
	if !strings.Contains(halted, "has logged 3 error trace(s)") || !strings.Contains(halted, "Traceback") {
		t.Fatalf("not halted on the traces: %v", f.rolloutSet)
	}
	if s := states(f, rid, ids)[1]; s != store.UpdateHostSkipped {
		t.Fatalf("nginx's second host is %q, want skipped", s)
	}
}

// A verified host opens a watch on each image that actually landed there, with a
// cursor at the moment of verification and a day to run.
func TestAVerifiedHostOpensAWatchOnWhatLanded(t *testing.T) {
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 0, BatchSize: 1})
	e := newEngine(f, &fakeDeployer{}, &fakeRunner{out: runningNew})
	at := time.Date(2026, 10, 4, 19, 39, 0, 0, time.UTC)
	e.now = func() time.Time { return at }
	e.Tick(context.Background())

	if s := states(f, rid, ids)[0]; s != store.UpdateHostVerified {
		t.Fatalf("host is %q, want verified", s)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.watches) != 1 {
		t.Fatalf("watches = %+v, want one", f.watches)
	}
	w := f.watches[0]
	if w.Repository != "nginx" || w.ToTag != "1.27" || w.HostID != ids[0] || w.RolloutID != rid {
		t.Errorf("watch = %+v", w)
	}
	if !w.CheckedAt.Equal(at) || !w.ExpiresAt.Equal(at.Add(WatchWindow)) {
		t.Errorf("cursor %v expires %v, want %v and %v", w.CheckedAt, w.ExpiresAt, at, at.Add(WatchWindow))
	}
}

// The watch reads the logs from its cursor, raises the regression once, and then
// leaves the container alone. Ten more ticks are not ten more notifications.
func TestTheWatchRaisesARegressionOnce(t *testing.T) {
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 0, BatchSize: 1})
	f.rollouts[0].State = store.UpdateRolloutCompleted // the rollout is long over
	at := time.Date(2026, 10, 4, 19, 39, 0, 0, time.UTC)
	_ = f.CreateRolloutWatches(context.Background(), rid, ids[0],
		[]store.RolloutImage{{Repository: "nginx", ToTag: "1.27"}}, at, WatchWindow)

	var scripts []string
	r := &fakeRunner{}
	r.respond = func(script string) (string, int, bool) {
		scripts = append(scripts, script)
		return "::OK::\nnginx:1.27\tweb\trunning\tnginx@sha256:x\thealthy\t0\t1\t" +
			"TypeError: open() got an unexpected keyword argument 'metadata_errors'\n", 0, false
	}
	n := &fakeNotifier{}
	e := newEngine(f, &fakeDeployer{}, r)
	e.SetNotifier(n)

	// Too soon: the cursor is only a minute old.
	e.now = func() time.Time { return at.Add(time.Minute) }
	e.Tick(context.Background())
	if len(scripts) != 0 {
		t.Fatalf("read the logs a minute after the cursor; the cadence is %s", WatchEvery)
	}

	e.now = func() time.Time { return at.Add(WatchEvery) }
	e.Tick(context.Background())
	if len(scripts) != 1 || !strings.Contains(scripts[0], "_since='2026-10-04T19:39:00Z'") {
		t.Fatalf("scripts = %q, want one read from the cursor", scripts)
	}
	if len(n.events) != 1 {
		t.Fatalf("events = %+v, want one regression", n.events)
	}
	ev := n.events[0]
	if ev.Type != notify.EventContainerRolloutRegression || ev.Severity != notify.SeverityWarning {
		t.Errorf("event = %+v", ev)
	}
	if !strings.Contains(ev.Title, "nginx:1.27") || !strings.Contains(ev.Body, "metadata_errors") ||
		!strings.Contains(ev.Body, "passing its healthcheck") {
		t.Errorf("event = %+v", ev)
	}
	f.mu.Lock()
	w := f.watches[0]
	f.mu.Unlock()
	if w.RegressionAt == nil || !strings.Contains(w.Regression, "metadata_errors") {
		t.Errorf("watch did not record the regression: %+v", w)
	}

	for i := 1; i <= 10; i++ {
		e.now = func() time.Time { return at.Add(time.Duration(i+1) * WatchEvery) }
		e.Tick(context.Background())
	}
	if len(scripts) != 1 || len(n.events) != 1 {
		t.Fatalf("after the regression: %d reads and %d events, want 1 and 1", len(scripts), len(n.events))
	}
}

// A clean read moves the cursor and says nothing; an unreadable host moves
// nothing, so the logs it could not read are read next time rather than skipped.
// The watch ends when its window does.
func TestTheWatchMovesItsCursorOnlyOnARead(t *testing.T) {
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 0, BatchSize: 1})
	f.rollouts[0].State = store.UpdateRolloutCompleted
	at := time.Date(2026, 10, 4, 19, 39, 0, 0, time.UTC)
	_ = f.CreateRolloutWatches(context.Background(), rid, ids[0],
		[]store.RolloutImage{{Repository: "nginx", ToTag: "1.27"}}, at, WatchWindow)
	r := &fakeRunner{out: "::OK::\nnginx:1.27\tweb\trunning\tnginx@sha256:x\thealthy\t0\t0\t\n"}
	n := &fakeNotifier{}
	e := newEngine(f, &fakeDeployer{}, r)
	e.SetNotifier(n)

	cursor := func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.watches[0].CheckedAt
	}

	e.now = func() time.Time { return at.Add(WatchEvery) }
	e.Tick(context.Background())
	if !cursor().Equal(at.Add(WatchEvery)) || len(n.events) != 0 {
		t.Fatalf("clean read: cursor %v, events %d", cursor(), len(n.events))
	}

	r.mu.Lock()
	r.failed = true
	r.mu.Unlock()
	e.now = func() time.Time { return at.Add(2 * WatchEvery) }
	e.Tick(context.Background())
	if !cursor().Equal(at.Add(WatchEvery)) {
		t.Fatalf("an unreadable host moved the cursor to %v", cursor())
	}

	r.mu.Lock()
	r.failed = false
	r.calls = 0
	r.mu.Unlock()
	e.now = func() time.Time { return at.Add(WatchWindow + time.Hour) }
	e.Tick(context.Background())
	if r.calls != 0 {
		t.Fatalf("an expired watch still read the host")
	}
}
