package containerupdate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/store"
)

// The wrapper runs the operator's command in the stack's directory, under a
// timeout, and reports the exit code itself.
func TestTheVerifyCommandScriptWrapsTheCommand(t *testing.T) {
	s := verifyCommandScript("/opt/stacks/voice", "curl -fsS http://localhost:10300 && echo it's up")
	for _, want := range []string{
		"cd '/opt/stacks/voice'",
		"timeout 120 sh -c 'curl -fsS http://localhost:10300 && echo it'\\''s up'",
		`echo "::EXIT::$?"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if verifyCommandExit("some output\n::EXIT::3\n") != 3 || verifyCommandExit("no marker") != -1 {
		t.Errorf("exit parsing")
	}
}

// withVerify gives a host one managed nginx stack carrying a verify command. The
// fleet fixture's hosts have none: their compose files are the host's own, and a
// verify command is a property of a managed stack.
func withVerify(f *fakeStore, hostID uuid.UUID, dir, cmd string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stacks[hostID] = []store.ContainerStack{{
		ID: uuid.New(), HostID: hostID, Name: "web", Enabled: true, Path: dir,
		Compose: composeNginx, VerifyCommand: cmd,
	}}
}

// The soak re-check runs the stack's verify command on the canary and halts when
// it fails: the container was running, healthy and unrestarted, and the only
// thing wrong with it was that it did not work.
func TestASoakRecheckHaltsWhenTheVerifyCommandFails(t *testing.T) {
	f, rid, ids := fleetFixture(store.UpdateRollout{Canary: 1, BatchSize: 5, SoakSeconds: 300})
	withVerify(f, ids[0], "/opt/a", "curl -fsS http://localhost:10300/")
	var verifyRuns int
	r := &fakeRunner{}
	r.respond = func(script string) (string, int, bool) {
		if strings.Contains(script, "::EXIT::") {
			verifyRuns++
			return "curl: (22) The requested URL returned error: 500\n::EXIT::22\n", 22, true
		}
		if strings.Contains(script, "::IMAGES::") {
			return "::NORUNTIME::not modelled by this fake", 0, false
		}
		return verifyFleet, 0, false
	}
	e := newEngine(f, &fakeDeployer{}, r)
	start := time.Date(2026, 10, 4, 19, 39, 0, 0, time.UTC)
	e.now = func() time.Time { return start }
	e.Tick(context.Background())
	e.now = func() time.Time { return start.Add(time.Minute) }
	e.Tick(context.Background())
	if verifyRuns != 0 {
		t.Fatalf("the verify command ran before the soak was over")
	}
	// Six minutes: the soak (5m) is over, the watch's first read (10m) is not.
	e.now = func() time.Time { return start.Add(6 * time.Minute) }
	e.Tick(context.Background())

	halted := ""
	for _, s := range f.rolloutSet {
		if strings.Contains(s, store.UpdateRolloutHalted) {
			halted = s
		}
	}
	if verifyRuns != 1 || !strings.Contains(halted, "verify command on") || !strings.Contains(halted, "exited 22") ||
		!strings.Contains(halted, "error: 500") {
		t.Fatalf("runs=%d halted=%q", verifyRuns, halted)
	}
	if s := states(f, rid, ids)[1]; s != store.UpdateHostSkipped {
		t.Fatalf("nginx's second host is %q, want skipped", s)
	}
}

// A passing verify command is silent, and only stacks that name the repository
// are asked: a host's other stacks have nothing to say about this update.
func TestOnlyTheStacksNamingTheImageAreVerified(t *testing.T) {
	f, _, ids := fleetFixture(store.UpdateRollout{Canary: 1, BatchSize: 5, SoakSeconds: 300})
	withVerify(f, ids[0], "/opt/a", "true")
	f.mu.Lock()
	f.stacks[ids[0]] = append(f.stacks[ids[0]], store.ContainerStack{
		Name: "unrelated", Enabled: true, Path: "/opt/stacks/unrelated",
		Compose: "services:\n  db:\n    image: postgres:16\n", VerifyCommand: "false",
	})
	f.mu.Unlock()
	var ran []string
	r := &fakeRunner{}
	r.respond = func(script string) (string, int, bool) {
		if strings.Contains(script, "::EXIT::") {
			ran = append(ran, script)
			return "::EXIT::0\n", 0, false
		}
		if strings.Contains(script, "::IMAGES::") {
			return "::NORUNTIME::not modelled by this fake", 0, false
		}
		return verifyFleet, 0, false
	}
	e := newEngine(f, &fakeDeployer{}, r)
	start := time.Date(2026, 10, 4, 19, 39, 0, 0, time.UTC)
	for _, d := range []time.Duration{0, time.Minute, 6 * time.Minute} {
		d := d
		e.now = func() time.Time { return start.Add(d) }
		e.Tick(context.Background())
	}
	for _, s := range f.rolloutSet {
		if strings.Contains(s, store.UpdateRolloutHalted) {
			t.Fatalf("halted on a passing command: %q", s)
		}
	}
	if len(ran) != 1 || strings.Contains(ran[0], "'false'") {
		t.Fatalf("verify runs = %q, want the nginx stack's only", ran)
	}
}

// The watch runs the verify command on every read and raises the regression when
// it fails, even though the logs are clean.
func TestTheWatchRaisesWhenTheVerifyCommandFails(t *testing.T) {
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 0, BatchSize: 1})
	f.rollouts[0].State = store.UpdateRolloutCompleted
	withVerify(f, ids[0], "/opt/stacks/web", "docker exec web ./smoke")
	at := time.Date(2026, 10, 4, 19, 39, 0, 0, time.UTC)
	_ = f.CreateRolloutWatches(context.Background(), rid, ids[0],
		[]store.RolloutImage{{Repository: "nginx", ToTag: "1.27"}}, at, WatchWindow)
	r := &fakeRunner{}
	r.respond = func(script string) (string, int, bool) {
		if strings.Contains(script, "::EXIT::") {
			return "smoke: transcription returned nothing\n::EXIT::1\n", 1, true
		}
		return "::OK::\nnginx:1.27\tweb\trunning\tnginx@sha256:x\thealthy\t0\t0\t\n", 0, false
	}
	n := &fakeNotifier{}
	e := newEngine(f, &fakeDeployer{}, r)
	e.SetNotifier(n)
	e.now = func() time.Time { return at.Add(WatchEvery) }
	e.Tick(context.Background())
	if len(n.events) != 1 || !strings.Contains(n.events[0].Body, "exited 1") ||
		!strings.Contains(n.events[0].Body, "returned nothing") {
		t.Fatalf("events = %+v", n.events)
	}
}
