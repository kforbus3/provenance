package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fleet-terminal/backend/internal/release"
)

// fakeDocker records calls and can be told to fail a given operation.
type fakeDocker struct {
	loaded      []string
	composedUp  [][]string
	overrides   []string
	failCompose bool
}

func (f *fakeDocker) Load(_ context.Context, tar string) error {
	f.loaded = append(f.loaded, tar)
	return nil
}
func (f *fakeDocker) RunningImageID(_ context.Context, c string) (string, error) {
	return "sha256:deadbeef-" + c, nil
}
func (f *fakeDocker) Tag(_ context.Context, src, dst string) error { return nil }
func (f *fakeDocker) ComposeUp(_ context.Context, services []string, override string) error {
	f.composedUp = append(f.composedUp, services)
	f.overrides = append(f.overrides, override)
	if f.failCompose {
		return errors.New("simulated compose failure")
	}
	return nil
}

type fakeHealth struct {
	err   error
	gated []string // base URLs health-gated, in order
}

func (h *fakeHealth) WaitHealthy(_ context.Context, baseURL, _ string, _ time.Duration) error {
	h.gated = append(h.gated, baseURL)
	return h.err
}

// makeBundle writes a valid two-component signed (additive) bundle and returns its path + key.
func makeBundle(t *testing.T) (path string, pub ed25519.PublicKey) {
	return makeBundleCompat(t, release.CompatAdditive)
}

// makeBundleCompat is makeBundle with an explicit migration-compatibility.
func makeBundleCompat(t *testing.T, compat string) (path string, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := release.GenerateKey()
	dir := t.TempDir()
	mk := func(name, content string) release.ImageRef {
		p := filepath.Join(dir, name+".tar")
		os.WriteFile(p, []byte(content), 0o600)
		dg, sz, _ := release.HashFile(p)
		return release.ImageRef{Component: name, Image: "fleet-terminal-" + name, Tag: "v1.2.3", File: "images/" + name + ".tar", Digest: dg, Bytes: sz}
	}
	be := mk("backend", "backend-image")
	fe := mk("frontend", "frontend-image")
	m := release.Manifest{
		SchemaVersion: release.ManifestSchema, Version: "v1.2.3", MinFromVersion: "v1.0.0",
		Components: []string{"backend", "frontend"}, Images: []release.ImageRef{be, fe},
		MigrationCompatibility: compat,
	}
	mj, _ := json.Marshal(m)
	sig := release.Sign(mj, priv)
	path = filepath.Join(dir, "b.fleetup")
	f, _ := os.Create(path)
	release.WriteBundle(f, mj, sig, map[string]string{
		"images/backend.tar":  filepath.Join(dir, "backend.tar"),
		"images/frontend.tar": filepath.Join(dir, "frontend.tar"),
	})
	f.Close()
	return path, pub
}

func newUpdater(t *testing.T, pub ed25519.PublicKey, d Docker, h Health) *Updater {
	return &Updater{
		cfg:    Config{UpdatesDir: t.TempDir(), Project: "fleet-terminal", HealthTimeout: time.Second},
		docker: d, health: h, trusted: []ed25519.PublicKey{pub}, status: Status{State: "idle"},
	}
}

func TestApplySuccess(t *testing.T) {
	path, pub := makeBundle(t)
	fd := &fakeDocker{}
	u := newUpdater(t, pub, fd, &fakeHealth{})
	u.Apply(context.Background(), ApplyReq{Bundle: path, CurrentVersion: "v1.1.0", TargetVersion: "v1.2.3"})

	if s := u.getStatus(); s.State != "success" {
		t.Fatalf("state=%s err=%s log=%v", s.State, s.Error, s.Log)
	}
	if len(fd.loaded) != 2 {
		t.Fatalf("loaded %d images, want 2", len(fd.loaded))
	}
	// Frontend must be recreated before the backend.
	if len(fd.composedUp) != 2 || fd.composedUp[0][0] != "frontend" || fd.composedUp[1][0] != "backend" {
		t.Fatalf("compose order wrong: %v", fd.composedUp)
	}
}

func TestApplyRollsBackendReplicas(t *testing.T) {
	// Additive release + 2 backend replicas -> roll one at a time, health-gate each.
	path, pub := makeBundle(t) // makeBundle uses CompatAdditive
	fd := &fakeDocker{}
	fh := &fakeHealth{}
	u := newUpdater(t, pub, fd, fh)
	u.cfg.BackendServices = []string{"backend1", "backend2"}
	u.Apply(context.Background(), ApplyReq{Bundle: path, CurrentVersion: "v1.1.0", TargetVersion: "v1.2.3"})

	if s := u.getStatus(); s.State != "success" {
		t.Fatalf("state=%s err=%s", s.State, s.Error)
	}
	// Compose order: frontend, then backend1, then backend2 — each recreated alone.
	got := fd.composedUp
	if len(got) != 3 || got[0][0] != "frontend" || got[1][0] != "backend1" || got[2][0] != "backend2" {
		t.Fatalf("rolling order wrong: %v", got)
	}
	// Each replica health-gated in turn, by its own URL.
	if len(fh.gated) != 2 || fh.gated[0] != "http://backend1:8080" || fh.gated[1] != "http://backend2:8080" {
		t.Fatalf("per-replica health gating wrong: %v", fh.gated)
	}
}

func TestApplyBreakingReplacesReplicasTogether(t *testing.T) {
	// Breaking release + 2 replicas -> recreate both in ONE compose call (maintenance
	// window), gated once. Mixed versions would break the just-migrated DB.
	path, pub := makeBundleCompat(t, "breaking")
	fd := &fakeDocker{}
	fh := &fakeHealth{}
	u := newUpdater(t, pub, fd, fh)
	u.cfg.BackendServices = []string{"backend1", "backend2"}
	u.Apply(context.Background(), ApplyReq{Bundle: path, CurrentVersion: "v1.1.0", TargetVersion: "v1.2.3"})

	if s := u.getStatus(); s.State != "success" {
		t.Fatalf("state=%s err=%s", s.State, s.Error)
	}
	// frontend, then one call recreating BOTH backends together.
	got := fd.composedUp
	if len(got) != 2 || got[0][0] != "frontend" {
		t.Fatalf("compose calls wrong: %v", got)
	}
	last := got[1]
	if len(last) != 2 || last[0] != "backend1" || last[1] != "backend2" {
		t.Fatalf("breaking should recreate both backends in one call, got %v", last)
	}
	if len(fh.gated) != 1 {
		t.Fatalf("breaking should health-gate once, got %d", len(fh.gated))
	}
}

func TestApplyRollsBackOnUnhealthy(t *testing.T) {
	path, pub := makeBundle(t)
	fd := &fakeDocker{}
	u := newUpdater(t, pub, fd, &fakeHealth{err: errors.New("never came up")})
	u.Apply(context.Background(), ApplyReq{Bundle: path, CurrentVersion: "v1.1.0", TargetVersion: "v1.2.3"})

	s := u.getStatus()
	if s.State != "failed" {
		t.Fatalf("state=%s, want failed", s.State)
	}
	// Expect: frontend up, backend up, then a rollback compose using the rollback override.
	if len(fd.composedUp) < 3 {
		t.Fatalf("expected a rollback compose call, got %v", fd.composedUp)
	}
	last := fd.overrides[len(fd.overrides)-1]
	if filepath.Base(last) != "docker-compose.rollback.yml" {
		t.Fatalf("last compose should use the rollback override, got %s", last)
	}
}

func TestApplyRejectsUntrustedBundle(t *testing.T) {
	path, _ := makeBundle(t)
	otherPub, _, _ := release.GenerateKey()
	u := newUpdater(t, otherPub, &fakeDocker{}, &fakeHealth{})
	u.Apply(context.Background(), ApplyReq{Bundle: path, CurrentVersion: "v1.1.0", TargetVersion: "v1.2.3"})
	if s := u.getStatus(); s.State != "failed" {
		t.Fatalf("expected failed on untrusted bundle, got %s", s.State)
	}
}

func TestWriteOverride(t *testing.T) {
	p := filepath.Join(t.TempDir(), "o.yml")
	if err := writeOverride(p, map[string]string{"backend": "fleet-terminal-backend:v1.2.3"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	got := string(b)
	for _, want := range []string{"backend:", "image: fleet-terminal-backend:v1.2.3", "pull_policy: never"} {
		if !strings.Contains(got, want) {
			t.Errorf("override missing %q:\n%s", want, got)
		}
	}
}
