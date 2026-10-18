package containerupdate

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// settleHost models the host side of a multi-image rollout over the Nextcloud
// stack: what each repository's read-back says, and how that changes once a
// deploy has recreated it. A recreated container reports "starting" for its
// first `startingPolls` read-backs and then `then` -- which is what Nextcloud's
// status.php healthcheck does while its entrypoint runs `occ upgrade`.
type settleHost struct {
	mu            sync.Mutex
	d             *fakeDeployer
	startingPolls int
	then          string // health once it stops "starting": healthy, unhealthy
	polls         map[string]int
	// events is the order things happened in on the host: "deploy:<services>"
	// and "poll:<repo>:<health>".
	events []string
	seen   int // deploys already turned into events
}

var settleRepos = []struct{ repo, tag, digest, names string }{
	{"nextcloud", "35.0.2-apache", "sha256:nc", "nextcloud-nextcloud-1 nextcloud-nextcloud-cron-1"},
	{"linuxserver/mariadb", "11.8.8", "sha256:db", "nextcloud-db-1"},
	{"onlyoffice/documentserver", "10.0", "sha256:oo", "OnlyOffice"},
}

func (h *settleHost) respond(script string) (string, int, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.d.mu.Lock()
	for _, svcs := range h.d.services[h.seen:] {
		h.events = append(h.events, "deploy:"+svcs)
	}
	h.seen = len(h.d.services)
	h.d.mu.Unlock()

	for _, r := range settleRepos {
		if !strings.Contains(script, shellCase(r.repo)) {
			continue
		}
		h.polls[r.repo]++
		health := "starting"
		if h.polls[r.repo] > h.startingPolls {
			health = h.then
		}
		// The first read-back of a repository is the deploy-time verification,
		// which does not judge health; the rest are settle polls.
		if h.polls[r.repo] > 1 {
			h.events = append(h.events, fmt.Sprintf("poll:%s:%s", r.repo, health))
		}
		var b strings.Builder
		b.WriteString("::OK::\n")
		for _, name := range strings.Fields(r.names) {
			fmt.Fprintf(&b, "%s:%s\t%s\trunning\t%s@%s,\t%s\t0\t0\t\n",
				r.repo, r.tag, name, r.repo, r.digest, health)
		}
		return b.String(), 0, false
	}
	return "::NORUNTIME::", 0, false
}

// settleFixture is one host running the Nextcloud stack, and a rollout over the
// given images.
func settleFixture(images ...store.RolloutImage) (*fakeStore, uuid.UUID, uuid.UUID) {
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	host := ids[0]
	stacks, containers := nextcloudHost()
	stacks[0].HostID = host
	f.stacks[host] = stacks
	f.containers[host] = containers
	f.images[rid] = images
	return f, rid, host
}

var (
	imNextcloud = store.RolloutImage{Repository: "nextcloud", FromTag: "35.0.1-apache",
		ToTag: "35.0.2-apache", TargetDigest: "sha256:nc"}
	imMariadb = store.RolloutImage{Repository: "linuxserver/mariadb", FromTag: "11.8.8",
		ToTag: "11.8.8", TargetDigest: "sha256:db"}
	imOnlyoffice = store.RolloutImage{Repository: "onlyoffice/documentserver", FromTag: "10.0",
		ToTag: "10.0", TargetDigest: "sha256:oo"}
)

func run(t *testing.T, f *fakeStore, h *settleHost) *Engine {
	t.Helper()
	e := newEngine(f, h.d, &fakeRunner{respond: h.respond})
	e.Tick(context.Background())
	return e
}

func hostState(f *fakeStore, rid, host uuid.UUID) store.UpdateRolloutHost {
	for _, h := range f.hosts[rid] {
		if h.HostID == host {
			return h
		}
	}
	return store.UpdateRolloutHost{}
}

// The incident, replayed through Tick: the rollout lists nextcloud first. The
// database has to be recreated first, and nextcloud only once it has settled.
func TestTheIncidentRolloutNoLongerRecreatesTheDatabaseUnderTheMigration(t *testing.T) {
	f, rid, host := settleFixture(imNextcloud, imMariadb)
	h := &settleHost{d: &fakeDeployer{}, startingPolls: 3, then: "healthy", polls: map[string]int{}}
	run(t, f, h)

	if got := hostState(f, rid, host); got.State != store.UpdateHostVerified {
		t.Fatalf("host %s: %s", got.State, got.Error)
	}
	if len(h.d.services) != 2 {
		t.Fatalf("deployed %v, want the database and then nextcloud", h.d.services)
	}
	if h.d.services[0] != "db" {
		t.Fatalf("first deploy was %q: the application went before the database it migrates", h.d.services[0])
	}
	if !strings.Contains(h.d.services[1], "nextcloud") {
		t.Fatalf("second deploy was %q, want nextcloud", h.d.services[1])
	}
	// Nextcloud was deployed only after the database reported healthy.
	events := strings.Join(h.events, " | ")
	dbHealthy := strings.Index(events, "poll:linuxserver/mariadb:healthy")
	ncDeploy := strings.Index(events, "deploy:nextcloud")
	if dbHealthy < 0 || ncDeploy < 0 || dbHealthy > ncDeploy {
		t.Fatalf("nextcloud was deployed before the database finished starting:\n%s", events)
	}
}

// The wait on its own, with two images that do not depend on each other: the
// second is not deployed while the first is still "starting".
func TestTheNextImageWaitsForTheLastOneToFinishStarting(t *testing.T) {
	f, rid, host := settleFixture(imNextcloud, imOnlyoffice)
	h := &settleHost{d: &fakeDeployer{}, startingPolls: 4, then: "healthy", polls: map[string]int{}}
	run(t, f, h)

	if got := hostState(f, rid, host); got.State != store.UpdateHostVerified {
		t.Fatalf("host %s: %s", got.State, got.Error)
	}
	events := strings.Join(h.events, " | ")
	if strings.Count(events, "poll:nextcloud:starting") != 3 {
		t.Errorf("want three polls of a still-starting nextcloud before moving on:\n%s", events)
	}
	if strings.Index(events, "poll:nextcloud:healthy") > strings.Index(events, "deploy:onlyoffice") {
		t.Fatalf("onlyoffice was deployed while nextcloud was still starting:\n%s", events)
	}
}

func TestAnUnhealthyUpdateStopsTheHostBeforeItsNextImage(t *testing.T) {
	f, rid, host := settleFixture(imNextcloud, imOnlyoffice)
	h := &settleHost{d: &fakeDeployer{}, startingPolls: 1, then: "unhealthy", polls: map[string]int{}}
	run(t, f, h)

	got := hostState(f, rid, host)
	if got.State != store.UpdateHostFailed {
		t.Fatalf("host %s, want failed", got.State)
	}
	if !strings.Contains(got.Error, "unhealthy") || !strings.Contains(got.Error, "not applied") {
		t.Errorf("failure does not say what happened: %q", got.Error)
	}
	if len(h.d.services) != 1 {
		t.Fatalf("deployed %v: the next image went out on top of an unhealthy service", h.d.services)
	}
}

func TestAContainerThatNeverFinishesStartingTimesOut(t *testing.T) {
	f, rid, host := settleFixture(imNextcloud, imOnlyoffice)
	h := &settleHost{d: &fakeDeployer{}, startingPolls: 1 << 30, polls: map[string]int{}}
	e := newEngine(f, h.d, &fakeRunner{respond: h.respond})
	var slept time.Duration
	e.sleep = func(_ context.Context, d time.Duration) error { slept += d; return nil }
	e.Tick(context.Background())

	got := hostState(f, rid, host)
	if got.State != store.UpdateHostFailed || !strings.Contains(got.Error, "had not finished starting") {
		t.Fatalf("host %s: %q", got.State, got.Error)
	}
	if slept < SettleTimeout-settleInterval || slept > SettleTimeout {
		t.Errorf("waited %s, want about %s", slept, SettleTimeout)
	}
	if len(h.d.services) != 1 {
		t.Fatalf("deployed %v after giving up", h.d.services)
	}
}

// The last image on a host has nothing behind it to collide with: no wait, and
// the soak judges it as before.
func TestTheLastImageOnAHostIsNotWaitedOn(t *testing.T) {
	f, rid, host := settleFixture(imNextcloud)
	h := &settleHost{d: &fakeDeployer{}, startingPolls: 1 << 30, polls: map[string]int{}}
	run(t, f, h)
	if got := hostState(f, rid, host); got.State != store.UpdateHostVerified {
		t.Fatalf("host %s: %s", got.State, got.Error)
	}
	if h.polls["nextcloud"] != 1 {
		t.Errorf("read back %d times, want once (the verification)", h.polls["nextcloud"])
	}
}

// A container with no healthcheck has nothing to wait for.
func TestAContainerWithNoHealthcheckIsSettledAtOnce(t *testing.T) {
	f, rid, host := settleFixture(imNextcloud, imOnlyoffice)
	h := &settleHost{d: &fakeDeployer{}, startingPolls: 0, then: "", polls: map[string]int{}}
	run(t, f, h)
	if got := hostState(f, rid, host); got.State != store.UpdateHostVerified {
		t.Fatalf("host %s: %s", got.State, got.Error)
	}
	if h.polls["nextcloud"] != 2 {
		t.Errorf("nextcloud read back %d times, want 2 (verify + one settle poll)", h.polls["nextcloud"])
	}
}
