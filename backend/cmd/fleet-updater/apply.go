package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
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
	// InspectMount returns the host source path of a container's bind/volume mount at
	// the given destination (used so the self-update helper mounts the real host paths).
	InspectMount(ctx context.Context, container, destination string) (string, error)
	// RunDetached launches a throwaway `docker run -d --rm` container from image with
	// the given host binds, overriding the entrypoint to run shellCmd via /bin/sh -c.
	RunDetached(ctx context.Context, image string, binds []string, shellCmd string) error
}

// Health waits for a backend instance (at baseURL) to come back healthy on the wanted
// version. Per-URL so a rolling upgrade can health-gate each replica individually.
type Health interface {
	WaitHealthy(ctx context.Context, baseURL, wantVersion string, timeout time.Duration) error
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
	u.persistLocked()
}

func (u *Updater) fail(msg string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := time.Now()
	u.status.State, u.status.Error, u.status.UpdatedAt = "failed", msg, &now
	u.status.Log = append(u.status.Log, fmt.Sprintf("%s: FAILED: %s", now.UTC().Format("15:04:05"), msg))
	u.persistLocked()
}

// statusPath is where the updater mirrors its status to disk (the shared updates
// volume). This lets the status survive the updater's OWN replacement during a
// self-update: the new updater loads it on boot and keeps reporting the final result.
func (u *Updater) statusPath() string { return filepath.Join(u.cfg.UpdatesDir, "status.json") }

// persistLocked writes the current status to disk. Caller must hold u.mu. Best-effort:
// a write failure must never abort an in-flight upgrade, so the error is only logged.
func (u *Updater) persistLocked() {
	b, err := json.Marshal(u.status)
	if err != nil {
		return
	}
	_ = os.WriteFile(u.statusPath(), b, 0o644)
}

// loadPersistedStatus restores the last persisted status at boot, so a self-update (or
// any updater restart) doesn't lose the result the UI is polling for.
func (u *Updater) loadPersistedStatus() {
	b, err := os.ReadFile(u.statusPath())
	if err != nil {
		return
	}
	var s Status
	if json.Unmarshal(b, &s) == nil && s.State != "" {
		u.mu.Lock()
		u.status = s
		u.mu.Unlock()
	}
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
	u.persistLocked()
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

	// 1b. Additive config migration. Merge any new .env keys this release needs (with
	// generated secrets where flagged) BEFORE recreating containers, so the recreated
	// services — and, last, the updater itself — come up already seeing them. Strictly
	// additive: operator-set values are never overwritten.
	if len(m.ConfigAdditions) > 0 {
		u.set("running", "applying config additions")
		added, cerr := applyConfigAdditions(u.cfg.EnvFile, m.ConfigAdditions)
		if cerr != nil {
			u.fail("config migration failed: " + cerr.Error())
			return
		}
		if len(added) > 0 {
			u.set("running", "added config keys: "+strings.Join(added, ", "))
		}
	}

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
	// whatever tag they currently carry) so a failed upgrade can be reverted. Keyed by
	// compose SERVICE — a component may map to several services (HA backend replicas).
	rollbackTags := map[string]string{} // service -> rollback image ref
	for _, im := range sortedImages(m.Images) {
		// The updater is swapped last, out of band, after success — it is never part of
		// an inline rollback (rolling it back inline would kill this process).
		if im.Component == updaterComponent {
			continue
		}
		rb := fmt.Sprintf("%s:rollback", im.Image)
		for _, svc := range u.servicesFor(im.Component) {
			container := fmt.Sprintf("%s-%s-1", u.cfg.Project, svc)
			id, err := u.docker.RunningImageID(ctx, container)
			if err != nil {
				// If the container/image can't be inspected we can still upgrade, but we
				// lose the rollback anchor for it — record and continue.
				u.set("running", fmt.Sprintf("note: no rollback anchor for %s (%v)", svc, err))
				continue
			}
			if err := u.docker.Tag(ctx, id, rb); err != nil {
				u.fail(fmt.Sprintf("tag rollback %s: %v", svc, err))
				return
			}
			rollbackTags[svc] = rb
		}
	}

	// 5. Apply new images, keyed by compose SERVICE (a component may map to several
	// services — HA backend replicas). Order: frontend first (invisible), sidecars, then
	// the backend.
	serviceImages := map[string]string{}
	for _, im := range m.Images {
		for _, svc := range u.servicesFor(im.Component) {
			serviceImages[svc] = fmt.Sprintf("%s:%s", im.Image, im.Tag)
		}
	}
	overridePath := filepath.Join(u.cfg.UpdatesDir, "docker-compose.upgrade.yml")
	if err := writeOverride(overridePath, serviceImages); err != nil {
		u.fail("write compose override: " + err.Error())
		return
	}
	comps := map[string]bool{}
	for _, c := range m.Components {
		comps[c] = true
	}

	if comps["frontend"] {
		u.set("running", "updating frontend")
		if err := u.docker.ComposeUp(ctx, []string{"frontend"}, overridePath); err != nil {
			u.rollback(ctx, rollbackTags, req, "frontend update failed: "+err.Error())
			return
		}
	}
	// Non-backend, non-frontend sidecars (e.g. grype-scanner): recreate together, no
	// health gate (they're stateless helpers, not on the request path).
	var sidecars []string
	for _, c := range m.Components {
		// fleet-updater is handled last, via a detached helper — it cannot recreate its
		// own container inline (that would kill this process mid-apply).
		if c != "frontend" && c != "backend" && c != updaterComponent {
			sidecars = append(sidecars, c)
		}
	}
	sort.Strings(sidecars)
	if len(sidecars) > 0 {
		u.set("running", "updating "+strings.Join(sidecars, ", "))
		if err := u.docker.ComposeUp(ctx, sidecars, overridePath); err != nil {
			u.rollback(ctx, rollbackTags, req, "sidecar update failed: "+err.Error())
			return
		}
	}

	// 6. Backend. Roll one replica at a time for an ADDITIVE release (peers keep serving,
	// mixed versions are safe), or recreate all replicas together for a BREAKING release
	// (a brief outage, but mixed versions would break the just-migrated DB). Migrations
	// apply on the first replica's boot; peers' migrate-on-boot then no-ops (advisory
	// lock + schema_migrations). Leadership handoff is automatic.
	if comps["backend"] {
		backends := u.servicesFor("backend")
		rolling := m.MigrationCompatibility == release.CompatAdditive && len(backends) > 1
		if rolling {
			for _, svc := range backends {
				u.set("running", "rolling "+svc+" (additive)")
				if err := u.docker.ComposeUp(ctx, []string{svc}, overridePath); err != nil {
					u.rollback(ctx, rollbackTags, req, svc+" update failed: "+err.Error())
					return
				}
				if err := u.health.WaitHealthy(ctx, u.backendHealthURL(svc), m.Version, u.cfg.HealthTimeout); err != nil {
					u.rollback(ctx, rollbackTags, req, svc+" did not become healthy: "+err.Error())
					return
				}
			}
		} else {
			if len(backends) > 1 {
				u.set("running", "updating all backends together (breaking migrations — brief outage)")
			} else {
				u.set("running", "updating backend")
			}
			if err := u.docker.ComposeUp(ctx, backends, overridePath); err != nil {
				u.rollback(ctx, rollbackTags, req, "backend update failed: "+err.Error())
				return
			}
			if err := u.health.WaitHealthy(ctx, u.backendHealthURL(backends[0]), m.Version, u.cfg.HealthTimeout); err != nil {
				u.rollback(ctx, rollbackTags, req, "new version did not become healthy: "+err.Error())
				return
			}
		}
	}

	u.mu.Lock()
	now2 := time.Now()
	u.status.State, u.status.Step, u.status.UpdatedAt = "success", "upgrade complete", &now2
	u.status.Log = append(u.status.Log, fmt.Sprintf("%s: upgraded to %s", now2.UTC().Format("15:04:05"), m.Version))
	u.persistLocked()
	u.mu.Unlock()

	// 7. Self-update LAST, only after everything else has succeeded and the success
	// status is on disk. The updater can't recreate its own container inline, so it
	// hands the swap to a detached helper (see selfUpdate). The upgrade is already
	// "success" from the operator's view; this replaces the updater in the background.
	if comps[updaterComponent] {
		if err := u.selfUpdate(ctx, serviceImages[updaterComponent]); err != nil {
			// Non-fatal: the app upgrade succeeded; only the updater's own refresh
			// didn't start. Record it in the log rather than failing the upgrade.
			u.set("success", "note: self-update handoff failed ("+err.Error()+") — updater still on previous version")
		} else {
			u.set("success", "handed off updater self-update to a detached helper")
		}
	}
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
	_ = u.health.WaitHealthy(ctx, u.backendHealthURL(u.servicesFor("backend")[0]), "", u.cfg.HealthTimeout)
	u.fail(reason + " (rolled back to the previous version)")
}

// updaterComponent is the one component that upgrades the updater itself. It is a
// compose service like any other, but recreating it can't be done inline (the updater
// would kill the process running the upgrade), so it is handled via selfUpdate.
const updaterComponent = "fleet-updater"

// selfUpdate replaces the fleet-updater container with newImage, out of band. The
// updater can't run `compose up fleet-updater` itself — that recreate would kill this
// very process before it finished — so it launches a short-lived DETACHED helper
// (watchtower-style) from the new image, which waits a moment, recreates the updater
// via compose (pinned to the new image by the upgrade override), then exits. The
// helper mounts the same compose files + .env as this updater, discovered by inspecting
// this container's own mounts so we use the correct HOST paths.
func (u *Updater) selfUpdate(ctx context.Context, newImage string) error {
	if newImage == "" {
		return fmt.Errorf("no image for %s in manifest", updaterComponent)
	}
	self := fmt.Sprintf("%s-%s-1", u.cfg.Project, updaterComponent)
	composeSrc, err := u.docker.InspectMount(ctx, self, "/compose")
	if err != nil || composeSrc == "" {
		return fmt.Errorf("locate compose mount host path: %v", err)
	}
	envSrc, err := u.docker.InspectMount(ctx, self, u.cfg.EnvFile)
	if err != nil || envSrc == "" {
		return fmt.Errorf("locate env-file mount host path: %v", err)
	}
	overridePath := filepath.Join(u.cfg.UpdatesDir, "docker-compose.upgrade.yml")

	// Build the compose invocation the helper runs (identical shape to ComposeUp).
	args := []string{"compose", "--env-file", u.cfg.EnvFile}
	for _, f := range u.cfg.ComposeFiles {
		args = append(args, "-f", f)
	}
	args = append(args, "-f", overridePath, "up", "-d", "--no-build", "--no-deps", updaterComponent)
	// A settle delay lets this /apply request finish and the updater mark success before
	// its container is torn down and replaced.
	script := "sleep 5; docker " + strings.Join(args, " ")

	binds := []string{
		"/var/run/docker.sock:/var/run/docker.sock",
		composeSrc + ":/compose:ro",
		envSrc + ":" + u.cfg.EnvFile + ":ro",
		u.cfg.Project + "_updates:" + u.cfg.UpdatesDir,
	}
	return u.docker.RunDetached(ctx, newImage, binds, script)
}

// servicesFor maps a manifest component to its compose service name(s). Only the
// backend component fans out to multiple services (HA replicas via cfg.BackendServices).
func (u *Updater) servicesFor(component string) []string {
	if component == "backend" && len(u.cfg.BackendServices) > 0 {
		return u.cfg.BackendServices
	}
	return []string{component}
}

// backendHealthURL returns the health base URL for a backend service. The default
// single "backend" uses the configured URL; HA replicas derive from the service name
// (compose gives each service its own DNS name; the backend always listens on 8080).
func (u *Updater) backendHealthURL(service string) string {
	if service == "backend" && u.cfg.BackendURL != "" {
		return u.cfg.BackendURL
	}
	return "http://" + service + ":8080"
}

func sortedImages(imgs []release.ImageRef) []release.ImageRef {
	out := append([]release.ImageRef(nil), imgs...)
	sort.Slice(out, func(i, j int) bool { return out[i].Component < out[j].Component })
	return out
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
