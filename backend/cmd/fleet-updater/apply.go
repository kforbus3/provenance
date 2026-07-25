package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fleet-terminal/backend/internal/release"
)

// Status mirrors the backend's upgrade.Status JSON shape so the backend can proxy it
// verbatim to the UI. The updater is the source of truth once an apply starts,
// because it survives the backend restart.
type Status struct {
	State         string     `json:"state"` // idle|running|success|failed
	TargetVersion string     `json:"targetVersion,omitempty"`
	Step          string     `json:"step,omitempty"`
	Log           []string   `json:"log,omitempty"`
	Error         string     `json:"error,omitempty"`
	StartedAt     *time.Time `json:"startedAt,omitempty"`
	UpdatedAt     *time.Time `json:"updatedAt,omitempty"`
}

// Docker is the minimal Docker surface the updater needs, behind an interface so the
// apply/rollback state machine is unit-testable without a real daemon.
type Docker interface {
	Load(ctx context.Context, tarPath string) error
	RunningImageID(ctx context.Context, container string) (string, error)
	Tag(ctx context.Context, src, dst string) error
	ComposeUp(ctx context.Context, services []string, overrideFile string) error
}

// Health waits for the backend to come back healthy on the wanted version.
type Health interface {
	WaitHealthy(ctx context.Context, wantVersion string, timeout time.Duration) error
}

// Updater orchestrates one bundle application over the Docker socket.
type Updater struct {
	cfg     Config
	docker  Docker
	health  Health
	trusted []ed25519.PublicKey

	mu     sync.Mutex
	status Status
}

// ApplyReq is what the backend posts to /apply.
type ApplyReq struct {
	Bundle         string `json:"bundle"`
	CurrentVersion string `json:"currentVersion"`
	TargetVersion  string `json:"targetVersion"`
}

func (u *Updater) getStatus() Status {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.status
}

func (u *Updater) set(state, step string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := time.Now()
	u.status.State, u.status.Step, u.status.UpdatedAt = state, step, &now
	u.status.Log = append(u.status.Log, fmt.Sprintf("%s: %s", now.UTC().Format("15:04:05"), step))
}

func (u *Updater) fail(msg string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := time.Now()
	u.status.State, u.status.Error, u.status.UpdatedAt = "failed", msg, &now
	u.status.Log = append(u.status.Log, fmt.Sprintf("%s: FAILED: %s", now.UTC().Format("15:04:05"), msg))
}

// busy reports whether an apply is already running.
func (u *Updater) busy() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.status.State == "running"
}

// Apply runs the full pipeline. It is synchronous; the HTTP handler runs it in a
// goroutine and clients poll getStatus.
func (u *Updater) Apply(ctx context.Context, req ApplyReq) {
	u.mu.Lock()
	now := time.Now()
	u.status = Status{State: "running", TargetVersion: req.TargetVersion, StartedAt: &now, UpdatedAt: &now}
	u.mu.Unlock()

	// 1. Independently re-verify the bundle — the updater never trusts the backend.
	u.set("running", "verifying bundle signature")
	b, err := release.Open(req.Bundle, u.trusted)
	if err != nil {
		u.fail("signature verification failed: " + err.Error())
		return
	}
	defer b.Close()
	if err := b.Manifest.CheckUpgradeable(req.CurrentVersion); err != nil {
		u.fail(err.Error())
		return
	}
	m := b.Manifest

	// 2. Extract + digest-verify images to a temp dir under the updates volume.
	u.set("running", "extracting images")
	imgDir := filepath.Join(u.cfg.UpdatesDir, "images-"+m.Version)
	_ = os.RemoveAll(imgDir)
	if _, err := b.ExtractImages(imgDir); err != nil {
		u.fail("image extraction/verification failed: " + err.Error())
		return
	}
	defer os.RemoveAll(imgDir)

	// 3. docker load each image.
	for _, im := range sortedImages(m.Images) {
		u.set("running", "loading image "+im.Component)
		if err := u.docker.Load(ctx, filepath.Join(imgDir, filepath.Base(im.File))); err != nil {
			u.fail(fmt.Sprintf("docker load %s: %v", im.Component, err))
			return
		}
	}

	// 4. Tag the CURRENTLY-running images :rollback (by container image id, robust to
	// whatever tag they currently carry) so a failed upgrade can be reverted.
	rollbackTags := map[string]string{} // service -> rollback image ref
	for _, im := range sortedImages(m.Images) {
		container := fmt.Sprintf("%s-%s-1", u.cfg.Project, im.Component)
		id, err := u.docker.RunningImageID(ctx, container)
		if err != nil {
			// If the container/image can't be inspected we can still upgrade, but we
			// lose the rollback anchor for it — record and continue.
			u.set("running", fmt.Sprintf("note: no rollback anchor for %s (%v)", im.Component, err))
			continue
		}
		rb := fmt.Sprintf("%s:rollback", im.Image)
		if err := u.docker.Tag(ctx, id, rb); err != nil {
			u.fail(fmt.Sprintf("tag rollback %s: %v", im.Component, err))
			return
		}
		rollbackTags[im.Component] = rb
	}

	// 5. Apply new images: frontend first (invisible), then backend + others. The
	// backend has already drained itself; recreating it swaps in the new version.
	newTags := map[string]string{}
	for _, im := range m.Images {
		newTags[im.Component] = fmt.Sprintf("%s:%s", im.Image, im.Tag)
	}
	overridePath := filepath.Join(u.cfg.UpdatesDir, "docker-compose.upgrade.yml")
	if err := writeOverride(overridePath, newTags); err != nil {
		u.fail("write compose override: " + err.Error())
		return
	}
	front, rest := splitFrontendFirst(m.Components)
	if len(front) > 0 {
		u.set("running", "updating frontend")
		if err := u.docker.ComposeUp(ctx, front, overridePath); err != nil {
			u.rollback(ctx, rollbackTags, req, "frontend update failed: "+err.Error())
			return
		}
	}
	u.set("running", "updating backend")
	if err := u.docker.ComposeUp(ctx, rest, overridePath); err != nil {
		u.rollback(ctx, rollbackTags, req, "backend update failed: "+err.Error())
		return
	}

	// 6. Health-gate the new backend.
	u.set("running", "waiting for the new version to become healthy")
	if err := u.health.WaitHealthy(ctx, m.Version, u.cfg.HealthTimeout); err != nil {
		u.rollback(ctx, rollbackTags, req, "new version did not become healthy: "+err.Error())
		return
	}

	u.mu.Lock()
	now2 := time.Now()
	u.status.State, u.status.Step, u.status.UpdatedAt = "success", "upgrade complete", &now2
	u.status.Log = append(u.status.Log, fmt.Sprintf("%s: upgraded to %s", now2.UTC().Format("15:04:05"), m.Version))
	u.mu.Unlock()
}

// rollback reverts the app services to their :rollback images and waits for the old
// version to come back, then marks the upgrade failed with the original reason.
func (u *Updater) rollback(ctx context.Context, rollbackTags map[string]string, req ApplyReq, reason string) {
	u.set("running", "rolling back: "+reason)
	if len(rollbackTags) == 0 {
		u.fail(reason + " (no rollback anchor available — manual recovery required)")
		return
	}
	overridePath := filepath.Join(u.cfg.UpdatesDir, "docker-compose.rollback.yml")
	if err := writeOverride(overridePath, rollbackTags); err != nil {
		u.fail(reason + " (rollback override write failed: " + err.Error() + ")")
		return
	}
	services := make([]string, 0, len(rollbackTags))
	for svc := range rollbackTags {
		services = append(services, svc)
	}
	sort.Strings(services)
	if err := u.docker.ComposeUp(ctx, services, overridePath); err != nil {
		u.fail(reason + " (rollback failed: " + err.Error() + " — manual recovery required)")
		return
	}
	// Best-effort wait for the prior version; we don't know its exact string, so just
	// wait for readiness (empty wantVersion = any healthy version).
	_ = u.health.WaitHealthy(ctx, "", u.cfg.HealthTimeout)
	u.fail(reason + " (rolled back to the previous version)")
}

func sortedImages(imgs []release.ImageRef) []release.ImageRef {
	out := append([]release.ImageRef(nil), imgs...)
	sort.Slice(out, func(i, j int) bool { return out[i].Component < out[j].Component })
	return out
}

// splitFrontendFirst returns the frontend service(s) first and the rest after, so the
// invisible static-asset swap happens before the backend restart.
func splitFrontendFirst(components []string) (front, rest []string) {
	for _, c := range components {
		if c == "frontend" {
			front = append(front, c)
		} else {
			rest = append(rest, c)
		}
	}
	sort.Strings(front)
	sort.Strings(rest)
	return front, rest
}

// writeOverride writes a compose override that pins each service to a local image and
// disables pulling, so `compose up --no-build` uses exactly the loaded image.
func writeOverride(path string, serviceImages map[string]string) error {
	var b strings.Builder
	b.WriteString("services:\n")
	svcs := make([]string, 0, len(serviceImages))
	for s := range serviceImages {
		svcs = append(svcs, s)
	}
	sort.Strings(svcs)
	for _, s := range svcs {
		fmt.Fprintf(&b, "  %s:\n    image: %s\n    pull_policy: never\n", s, serviceImages[s])
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
