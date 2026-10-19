package containerupdate

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// The arrangement on `ai`, the GPU host that found both defects below.
//
// Three compose projects, one per mode, each holding a model server gated by a
// profile and a small ungated guard (so `up -d` always has something to start).
// Every one of them names the same llama.cpp image. ai-mode switches modes by
// writing COMPOSE_PROFILES into each project's .env.
//
// Every llama.cpp release halted "Update all" on this host: the rollout deployed
// the first project naming the image (`coding`), and the host-wide check then
// found flash-mode-guard still on the old tag. It happened on 2026-10-18 and
// again on 2026-10-19.
const (
	modeRepo = "ghcr.io/ggml-org/llama.cpp"
	modeFrom = "server-cuda-b11718"
	modeTo   = "server-cuda-b11723"
)

func modeCompose(mode, server string) string {
	return "services:\n" +
		"  " + mode + "-mode-guard:\n" +
		"    image: " + modeRepo + ":" + modeFrom + "\n" +
		"    entrypoint: [\"sleep\", \"infinity\"]\n" +
		"  " + server + ":\n" +
		"    image: " + modeRepo + ":" + modeFrom + "\n" +
		"    profiles: [" + mode + "]\n"
}

type modeHost struct {
	f      *fakeStore
	rid    uuid.UUID
	host   uuid.UUID
	stacks map[string]uuid.UUID // mode -> stack id
}

// modeFixture builds the host in one mode: every guard is up, and only the
// active mode's server is.
func modeFixture(active string) *modeHost {
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.rollouts[0].Repository, f.rollouts[0].FromTag, f.rollouts[0].ToTag = modeRepo, modeFrom, modeTo
	h := &modeHost{f: f, rid: rid, host: ids[0], stacks: map[string]uuid.UUID{}}

	servers := map[string]string{"coding": "qwen-coder", "creative": "creative-llm", "flash": "flash-llm"}
	f.stacks[h.host] = nil
	f.containers[h.host] = nil
	// Listed by name, which is how the store returns them and why `coding` was
	// always the one chosen.
	for _, mode := range []string{"coding", "creative", "flash"} {
		id := uuid.New()
		h.stacks[mode] = id
		dir := "/opt/stacks/" + mode
		f.stacks[h.host] = append(f.stacks[h.host], store.ContainerStack{
			ID: id, HostID: h.host, Name: mode, Path: dir, Enabled: true,
			Compose: modeCompose(mode, servers[mode])})
		up := []string{mode + "-mode-guard"}
		if mode == active {
			up = append(up, servers[mode])
		}
		for _, svc := range up {
			f.containers[h.host] = append(f.containers[h.host], models.Container{
				Name: svc, Repository: modeRepo, Tag: modeFrom,
				ComposeProject: mode, ComposeService: svc, ComposeDir: dir})
		}
	}
	return h
}

// runner answers the verify readback from what was actually deployed: a running
// container is on the new tag only if a deploy of its project named it, or named
// nothing (the whole project). That is what makes these tests able to fail -- a
// fixed "everything moved" answer would pass the code that left flash behind.
func (h *modeHost) runner(d *fakeDeployer) *fakeRunner {
	var mu sync.Mutex
	return &fakeRunner{respond: func(script string) (string, int, bool) {
		mu.Lock()
		defer mu.Unlock()
		d.mu.Lock()
		moved := map[string]bool{}
		for i, id := range d.stacks {
			for mode, sid := range h.stacks {
				if sid != id {
					continue
				}
				for _, c := range h.f.containers[h.host] {
					if c.ComposeProject != mode {
						continue
					}
					if d.services[i] == "" || strings.Contains(" "+d.services[i]+" ", " "+c.ComposeService+" ") {
						moved[c.Name] = true
					}
				}
			}
		}
		d.mu.Unlock()
		var b strings.Builder
		b.WriteString("::OK::\n")
		for _, c := range h.f.containers[h.host] {
			tag := modeFrom
			if moved[c.Name] {
				tag = modeTo
			}
			b.WriteString(modeRepo + ":" + tag + "\t" + c.Name + "\trunning\tx@sha256:new\n")
		}
		return b.String(), 0, false
	}}
}

func (h *modeHost) deployedFor(d *fakeDeployer, mode string) (string, bool) {
	for i, id := range d.stacks {
		if id == h.stacks[mode] {
			return d.services[i], true
		}
	}
	return "", false
}

func TestEveryModeProjectOnTheImageIsDeployed(t *testing.T) {
	h := modeFixture("coding")
	d := &fakeDeployer{}
	newEngine(h.f, d, h.runner(d)).Tick(context.Background())

	for _, mode := range []string{"coding", "creative", "flash"} {
		if _, ok := h.deployedFor(d, mode); !ok {
			t.Errorf("the %s project runs %s:%s and was not deployed (deployed: %v)",
				mode, modeRepo, modeFrom, d.services)
		}
	}
	got := h.f.hosts[h.rid][0]
	if got.State != store.UpdateHostVerified {
		t.Fatalf("host state = %q (%s), want verified", got.State, got.Error)
	}
	// Each file now names the new tag, including the switched-off servers, so a
	// later mode switch starts them on it.
	for _, st := range h.f.stacks[h.host] {
		if strings.Contains(st.Compose, modeFrom) {
			t.Errorf("the %s stack still names %s after the rollout:\n%s", st.Name, modeFrom, st.Compose)
		}
	}
}

// The other half: naming every service on the image bypassed the profiles.
// In creative mode a coding-stack deploy of "coding-mode-guard qwen-coder"
// started qwen-coder on the GPUs the creative servers were using.
func TestAProfileGatedServiceThatIsOffIsNotStarted(t *testing.T) {
	h := modeFixture("creative")
	d := &fakeDeployer{}
	newEngine(h.f, d, h.runner(d)).Tick(context.Background())

	coding, ok := h.deployedFor(d, "coding")
	if !ok {
		t.Fatalf("the coding project was not deployed: %v", d.services)
	}
	if strings.Contains(coding, "qwen-coder") {
		t.Errorf("deployed %q in creative mode, which starts qwen-coder past its profile", coding)
	}
	if coding != "coding-mode-guard" {
		t.Errorf("coding deploy named %q, want just the guard", coding)
	}
	// The active mode's server is up, so it IS named: it has to move.
	creative, _ := h.deployedFor(d, "creative")
	if !strings.Contains(creative, "creative-llm") {
		t.Errorf("creative deploy named %q; the running creative-llm has to move too", creative)
	}
	if got := h.f.hosts[h.rid][0]; got.State != store.UpdateHostVerified {
		t.Fatalf("host state = %q (%s), want verified", got.State, got.Error)
	}
}

// A project that names the image but has nothing up was stopped by somebody, and
// deploying it would start it.
func TestAStoppedProjectNamingTheImageIsNotStarted(t *testing.T) {
	h := modeFixture("coding")
	var kept []models.Container
	for _, c := range h.f.containers[h.host] {
		if c.ComposeProject != "flash" {
			kept = append(kept, c)
		}
	}
	h.f.containers[h.host] = kept
	d := &fakeDeployer{}
	newEngine(h.f, d, h.runner(d)).Tick(context.Background())

	if svcs, ok := h.deployedFor(d, "flash"); ok {
		t.Errorf("deployed the stopped flash project (%q), which starts it", svcs)
	}
	if got := h.f.hosts[h.rid][0]; got.State != store.UpdateHostVerified {
		t.Fatalf("host state = %q (%s), want verified", got.State, got.Error)
	}
}

// When every service on the image in a project is switched off, the deploy is
// the whole project: the only `up -d` form that honours profiles. It writes the
// new file and starts nothing that was off.
func TestAllServicesSwitchedOffDeploysTheWholeProject(t *testing.T) {
	compose := "services:\n" +
		"  llm:\n    image: " + modeRepo + ":" + modeFrom + "\n    profiles: [gpu]\n" +
		"  web:\n    image: nginx:1.27\n"
	e := newEngine(&fakeStore{containers: map[uuid.UUID][]models.Container{}}, &fakeDeployer{}, &fakeRunner{})
	r := store.UpdateRollout{Repository: modeRepo, FromTag: modeFrom, ToTag: modeTo}
	if got := e.composeServicesFor(context.Background(), r, uuid.New(), "/opt/stacks/x", compose); got != nil {
		t.Errorf("services = %q, want nil (the whole project)", got)
	}
}
