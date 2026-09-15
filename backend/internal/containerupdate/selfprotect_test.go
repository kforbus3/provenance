package containerupdate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// Provenance is upgraded by signed bundle, never by replacing its own containers.
//
// It is not only this product's own images — those are built locally and already
// excluded, having no registry digest. It is the third-party containers the
// application is MADE of. On a live instance:
//
//	provenance-postgres-1  postgres:16-alpine       project provenance
//	provenance-redis-1     redis:7-alpine           project provenance
//	provenance-guacd-1     guacamole/guacd:1.5.5    project provenance
//
// The database this server talks to, the cache holding its sessions, and the
// daemon carrying its remote-desktop connections. All ordinary registry images,
// all offered for update, and restarting the database under the running backend
// is the least bad thing that happens.
//
// A rollout of them could not even report what it did: the backend running the
// rollout is what gets restarted, so the result is never written.

func TestThisApplicationsOwnContainersAreRecognised(t *testing.T) {
	const self = "provenance"
	cases := []struct {
		name, project, image string
		want                 bool
		why                  string
	}{
		{"its database", self, "postgres:16-alpine", true,
			"a stock postgres image, but it is THIS instance's database"},
		{"its session cache", self, "redis:7-alpine", true, ""},
		{"its remote-desktop daemon", self, "guacamole/guacd:1.5.5", true, ""},
		{"its own backend", self, "provenance-backend:1.2.8", true, ""},
		{"an image named for the project but unlabelled", "", "provenance-jumphost", true,
			"labels may not have been collected; the image name still says what it is"},
		{"somebody else's postgres", "nextcloud", "postgres:16-alpine", false,
			"the same image in a different project is an ordinary container"},
		{"an unrelated container", "server", "debian-ab-http", false, ""},
		{"no project configured", "anything", "postgres:16", false,
			"with no self project nothing is protected, rather than everything"},
	}
	for _, c := range cases {
		self := self
		if c.name == "no project configured" {
			self = ""
		}
		if got := isSelfContainer(self, c.project, c.image); got != c.want {
			t.Errorf("%s: isSelfContainer(%q, %q, %q) = %v, want %v — %s",
				c.name, self, c.project, c.image, got, c.want, c.why)
		}
	}
}

type fakeSettings struct{ val string }

func (f *fakeSettings) GetSetting(_ context.Context, _ string) (json.RawMessage, error) {
	if f.val == "" {
		return nil, nil
	}
	b, _ := json.Marshal(f.val)
	return b, nil
}

func TestTheSelfProjectIsConfigurableAndDefaulted(t *testing.T) {
	// The project name comes from whoever ran compose. A deployment that renamed
	// it would otherwise have its own database offered for update, silently —
	// which is the exact failure this exists to prevent.
	if got := selfProject(context.Background(), &fakeSettings{val: "acme-fleet"}); got != "acme-fleet" {
		t.Errorf("configured value ignored: %q", got)
	}
	if got := selfProject(context.Background(), &fakeSettings{}); got != defaultSelfProject {
		t.Errorf("default = %q, want %q", got, defaultSelfProject)
	}
	if got := selfProject(context.Background(), nil); got != defaultSelfProject {
		t.Errorf("with no store: %q", got)
	}
}

func TestARolloutRefusesThisApplicationsOwnDatabase(t *testing.T) {
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.rollouts[0].Repository, f.rollouts[0].FromTag, f.rollouts[0].ToTag =
		"postgres", "16-alpine", "17-alpine"
	f.stacks[ids[0]] = nil
	f.containers[ids[0]] = []models.Container{{
		Name: "provenance-postgres-1", Image: "postgres:16-alpine",
		Repository: "postgres", Tag: "16-alpine",
		ComposeProject: "provenance", ComposeService: "postgres",
		ComposeDir: "/opt/fleet",
	}}
	d := &fakeDeployer{}
	newEngine(f, d, scripted("::OK::\n", composeNginx)).Tick(context.Background())

	if d.calls != 0 {
		t.Error("deployed over this application's own database")
	}
	h := f.hosts[rid][0]
	if h.State != store.UpdateHostFailed {
		t.Fatalf("state = %q, want failed", h.State)
	}
	if !strings.Contains(h.Error, "signed bundle") {
		t.Errorf("the reason should point at the bundle path, got %q", h.Error)
	}
}

func TestAnOrdinaryContainerOnTheSameHostIsStillUpdatable(t *testing.T) {
	// Protection is per container, not per host. control01 runs plenty that are
	// nothing to do with this application.
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.stacks[ids[0]] = nil
	f.containers[ids[0]] = []models.Container{
		{Name: "provenance-postgres-1", Image: "postgres:16-alpine",
			Repository: "postgres", Tag: "16-alpine", ComposeProject: "provenance"},
		{Name: "web", Image: "nginx:1.24", Repository: "nginx", Tag: "1.24",
			ComposeProject: "site", ComposeService: "web", ComposeDir: "/opt/site"},
	}
	f.rollouts[0].ToTag = "1.24" // a rebuild, so no adoption needed
	f.rollouts[0].TargetDigest = "sha256:new"
	newEngine(f, &fakeDeployer{}, scripted("::OK::\nnginx:1.24\tnginx\trunning\tnginx@sha256:new\n", "")).
		Tick(context.Background())

	if got := f.hosts[rid][0].State; got != store.UpdateHostVerified {
		t.Errorf("state = %q (%q) — an unrelated container on the same host must "+
			"still be updatable", got, f.hosts[rid][0].Error)
	}
}

var _ = uuid.New
