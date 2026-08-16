// Package upgrade drives the in-UI upgrade flow from the backend's side: it accepts a
// signed .fleetup bundle, verifies it against the trusted release keys, takes a
// pre-upgrade database backup, then hands the staged bundle to the privileged
// fleet-updater sidecar (which owns the Docker socket) to perform the container swap.
// The backend never touches Docker itself. It also owns "drain" — a per-instance flag
// that makes /ready fail so a load balancer ejects the instance and new sessions are
// refused ahead of a restart.
package upgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kforbus3/Moorgate/backend/internal/backup"
	"github.com/kforbus3/Moorgate/backend/internal/cluster"
	"github.com/kforbus3/Moorgate/backend/internal/config"
	"github.com/kforbus3/Moorgate/backend/internal/release"
	"github.com/kforbus3/Moorgate/backend/internal/store"
	"github.com/kforbus3/Moorgate/backend/internal/ws"
)

// Service coordinates upgrades and drain state for one backend instance.
type Service struct {
	store   *store.Store
	cfg     *config.Config
	log     *slog.Logger
	hub     *ws.Hub
	backup  *backup.Service
	version string
	trusted []ed25519.PublicKey
	client  *http.Client
	bootAt  time.Time // process start; updater statuses older than this are history

	mu       sync.Mutex
	draining bool
	local    Status // pre-dispatch/local status; the updater is source of truth once dispatched
}

// Status is the upgrade progress reported to the UI.
type Status struct {
	State         string     `json:"state"` // idle|verifying|backing_up|dispatched|running|success|failed
	TargetVersion string     `json:"targetVersion,omitempty"`
	Step          string     `json:"step,omitempty"`
	Log           []string   `json:"log,omitempty"`
	Error         string     `json:"error,omitempty"`
	Draining      bool       `json:"draining"`
	StartedAt     *time.Time `json:"startedAt,omitempty"`
	UpdatedAt     *time.Time `json:"updatedAt,omitempty"`
}

// New builds the service. Trusted release keys come from the binary-embedded key(s)
// plus cfg.ReleaseTrustKeys; a malformed FLEET_RELEASE_TRUST_KEYS is logged and
// ignored (embedded keys still apply) rather than failing startup. With no valid keys
// at all, verification fails closed and no upgrade can be applied.
func New(st *store.Store, cfg *config.Config, log *slog.Logger, hub *ws.Hub, bk *backup.Service, version string) *Service {
	trusted, err := release.TrustedKeys(cfg.ReleaseTrustKeys)
	if err != nil {
		log.Warn("upgrade: FLEET_RELEASE_TRUST_KEYS is malformed; using only embedded release keys", "err", err)
		trusted, _ = release.TrustedKeys("")
	}
	return &Service{
		store: st, cfg: cfg, log: log, hub: hub, backup: bk, version: version, trusted: trusted,
		client: &http.Client{Timeout: 30 * time.Second},
		local:  Status{State: "idle"},
		bootAt: time.Now(),
	}
}

// IsDraining reports whether this instance is draining (checked by /ready).
func (s *Service) IsDraining() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.draining
}

// SetDrain flips drain state and broadcasts a maintenance banner to connected UIs.
// Draining makes /ready fail (LB ejects) and signals the UI that a restart is imminent.
func (s *Service) SetDrain(on bool, message string) {
	s.mu.Lock()
	s.draining = on
	s.mu.Unlock()
	if s.hub != nil {
		s.hub.Broadcast("system.maintenance", map[string]any{"draining": on, "message": message})
	}
	s.log.Info("upgrade: drain state changed", "draining", on)
}

// stagedPath is where an uploaded bundle is written for the updater to read (shared
// volume, same path in both containers).
func (s *Service) stagedPath() string {
	return filepath.Join(s.cfg.UpdatesDir, "pending.fleetup")
}

// Stage streams an uploaded bundle to the updates volume, returns the on-disk path.
func (s *Service) Stage(r io.Reader) (string, error) {
	if err := os.MkdirAll(s.cfg.UpdatesDir, 0o700); err != nil {
		return "", err
	}
	path := s.stagedPath()
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(f, r); err != nil {
		return "", err
	}
	return path, nil
}

// Verify opens a staged bundle, checks its signature against the trusted release keys
// and that it is a valid, newer upgrade for the running version. Returns the manifest.
func (s *Service) Verify(path string) (release.Manifest, error) {
	b, err := release.Open(path, s.trusted)
	if err != nil {
		return release.Manifest{}, err
	}
	defer b.Close()
	if err := b.Manifest.CheckUpgradeable(s.version); err != nil {
		return release.Manifest{}, err
	}
	return b.Manifest, nil
}

// Apply verifies the staged bundle, takes a pre-upgrade DB backup, and dispatches the
// apply to the updater sidecar. It returns once dispatch succeeds; progress is then
// polled via Status (which proxies the updater). Only one apply may be in flight.
func (s *Service) Apply(ctx context.Context, path string, actorName string) error {
	m, err := s.Verify(path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	inProgress := s.local.State == "verifying" || s.local.State == "backing_up" || s.local.State == "dispatched"
	dispatched := s.local.State == "dispatched"
	s.mu.Unlock()
	if inProgress {
		// A local "dispatched" state persists after we hand off to the updater. If a
		// prior apply then failed (or finished) on the updater, that local state is
		// STALE and would otherwise block every future apply forever. Self-heal: if we
		// dispatched but the updater is no longer running, allow a new apply. Only a
		// genuinely-running updater (or an in-flight local verify/backup) blocks.
		blocked := true
		if dispatched {
			if us, ok := s.updaterStatus(ctx); ok && us.State != "running" {
				blocked = false // stale dispatched state; the updater is done/idle
			}
		}
		if blocked {
			return fmt.Errorf("an upgrade is already in progress")
		}
	}
	now := time.Now()
	s.mu.Lock()
	s.local = Status{State: "backing_up", TargetVersion: m.Version, StartedAt: &now, UpdatedAt: &now, Draining: s.draining, Step: "taking pre-upgrade database backup"}
	s.mu.Unlock()

	// Pre-upgrade snapshot (best effort but strongly preferred — surface failure).
	if s.backup != nil {
		if _, berr := s.backup.Create(ctx); berr != nil {
			s.fail(fmt.Sprintf("pre-upgrade backup failed: %v", berr))
			return fmt.Errorf("pre-upgrade backup failed: %w", berr)
		}
	}

	// Drain THIS instance before the updater recreates it: refuse new sessions, eject
	// from any load balancer (/ready fails), and banner connected UIs. The replacement
	// process starts un-drained, so this state dies with the old container.
	s.SetDrain(true, fmt.Sprintf("Upgrading to %s — reconnecting shortly.", m.Version))

	// Dispatch to the updater sidecar.
	body, _ := json.Marshal(map[string]string{"bundle": path, "currentVersion": s.version, "targetVersion": m.Version})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.UpdaterURL+"/apply", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.UpdaterToken != "" {
		req.Header.Set("X-Updater-Token", s.cfg.UpdaterToken)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		s.fail(fmt.Sprintf("could not reach the updater service: %v", err))
		return fmt.Errorf("updater unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		s.fail(fmt.Sprintf("updater rejected the upgrade (%d): %s", resp.StatusCode, string(msg)))
		return fmt.Errorf("updater error %d", resp.StatusCode)
	}
	s.mu.Lock()
	now2 := time.Now()
	s.local.State, s.local.Step, s.local.UpdatedAt = "dispatched", "applying update", &now2
	s.mu.Unlock()
	return nil
}

func (s *Service) fail(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.local.State, s.local.Error, s.local.UpdatedAt = "failed", msg, &now
}

// Status returns the current upgrade status. Once an apply is dispatched the updater
// sidecar is the source of truth (it survives the backend restart), so this proxies
// the updater's /status and falls back to local state if it's unreachable.
//
// A TERMINAL updater status (success/failed) that predates this backend process is
// a previous upgrade's outcome, not ours: the updater persists its last run
// indefinitely, and without this check a fresh apply briefly shows the prior run's
// "Upgraded to <old version>" before (or instead of) the real progress.
func (s *Service) Status(ctx context.Context) Status {
	if us, ok := s.updaterStatus(ctx); ok {
		terminal := us.State == "success" || us.State == "failed"
		stale := terminal && (us.UpdatedAt == nil || us.UpdatedAt.Before(s.bootAt))
		if !stale {
			us.Draining = s.IsDraining()
			return us
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.local
	st.Draining = s.draining
	return st
}

// ClusterMember is a compact view of a cluster instance for the upgrade UI, so an
// operator can see version skew across a multi-instance (HA) deployment during a
// rolling upgrade.
type ClusterMember struct {
	Hostname      string    `json:"hostname"`
	Version       string    `json:"version"`
	IsLeader      bool      `json:"isLeader"`
	LastHeartbeat time.Time `json:"lastHeartbeat"`
}

// SiteVersion is a compact view of a federation site's running build, shown on the
// hub's upgrade screen to enforce sites-first ordering (upgrade every site before the
// hub, so the hub never runs a newer protocol than a site it must talk to).
type SiteVersion struct {
	Name         string `json:"name"`
	BuildVersion string `json:"buildVersion"`
	Status       string `json:"status"`
	// UpToDate is true when the site already reports the version the hub is about to
	// move to (or, with no update pending, the hub's current version).
	UpToDate bool `json:"upToDate"`
}

// CheckResult is what the UI's "check for updates" returns.
type CheckResult struct {
	CurrentVersion  string                  `json:"currentVersion"`
	ChannelEnabled  bool                    `json:"channelEnabled"`
	UpdateAvailable bool                    `json:"updateAvailable"`
	Release         *release.ChannelRelease `json:"release,omitempty"`
	// Cluster is the live instance roster (>1 = clustered). Empty/one on single-host.
	Cluster []ClusterMember `json:"cluster,omitempty"`
	// Sites is the federation site roster (populated in hub mode only).
	Sites []SiteVersion `json:"sites,omitempty"`
	// SitesBehind is set when at least one federation site is not yet on the target
	// version — a signal to upgrade the sites before applying the hub upgrade.
	SitesBehind bool `json:"sitesBehind,omitempty"`
}

// clusterRoster returns the live instance roster for the upgrade UI (best-effort).
// Only instances with a heartbeat inside the lease window count: every unclean
// backend stop (crash, container swap) leaves its row behind until the leader's
// prune sweep, and counting those ghosts makes a single-instance deployment
// present itself as a multi-node cluster.
func (s *Service) clusterRoster(ctx context.Context) []ClusterMember {
	instances, err := s.store.ListClusterInstances(ctx)
	if err != nil {
		return nil
	}
	out := make([]ClusterMember, 0, len(instances))
	for _, in := range instances {
		if time.Since(in.LastHeartbeat) > cluster.Lease {
			continue
		}
		out = append(out, ClusterMember{Hostname: in.Hostname, Version: in.Version, IsLeader: in.IsLeader, LastHeartbeat: in.LastHeartbeat})
	}
	return out
}

// CheckForUpdate fetches the configured release channel and reports the newest
// applicable upgrade for the running version (nil if already current or no channel).
func (s *Service) CheckForUpdate(ctx context.Context) (CheckResult, error) {
	res := CheckResult{CurrentVersion: s.version, ChannelEnabled: s.cfg.UpdateChannelURL != "", Cluster: s.clusterRoster(ctx)}
	if !res.ChannelEnabled {
		return res, nil
	}
	idx, err := release.FetchChannel(ctx, s.client, s.cfg.UpdateChannelURL, s.trusted)
	if err != nil {
		return res, err
	}
	if up := idx.PickUpdate(s.version); up != nil {
		res.UpdateAvailable, res.Release = true, up
	}
	// Sites-first ordering: in hub mode, surface each site's build version against the
	// version this hub is about to move to, so an operator upgrades the sites first.
	target := s.version
	if res.Release != nil {
		target = res.Release.Version
	}
	res.Sites, res.SitesBehind = s.federationSites(ctx, target)
	return res, nil
}

// federationSites returns the site roster with an up-to-date flag against target, and
// whether any site is behind it. Empty unless this instance is a federation hub.
func (s *Service) federationSites(ctx context.Context, target string) ([]SiteVersion, bool) {
	if s.cfg == nil || s.cfg.Mode != "hub" {
		return nil, false
	}
	sites, err := s.store.ListSites(ctx)
	if err != nil || len(sites) == 0 {
		return nil, false
	}
	out := make([]SiteVersion, 0, len(sites))
	behind := false
	for _, site := range sites {
		// A site that already reports the target version is up to date. A site that has
		// never reported a version (empty) is treated as behind, since we can't confirm it.
		upToDate := site.BuildVersion != "" && site.BuildVersion == target
		if !upToDate {
			behind = true
		}
		out = append(out, SiteVersion{
			Name:         site.Name,
			BuildVersion: site.BuildVersion,
			Status:       site.Status,
			UpToDate:     upToDate,
		})
	}
	return out, behind
}

// PullAndApply downloads the channel release matching version (or the newest
// applicable one if version is empty), streams it to the staging area, and applies it
// through the same pipeline as an uploaded bundle.
func (s *Service) PullAndApply(ctx context.Context, version, actorName string) error {
	if s.cfg.UpdateChannelURL == "" {
		return fmt.Errorf("no update channel is configured")
	}
	idx, err := release.FetchChannel(ctx, s.client, s.cfg.UpdateChannelURL, s.trusted)
	if err != nil {
		return err
	}
	var rel *release.ChannelRelease
	if version == "" {
		rel = idx.PickUpdate(s.version)
	} else {
		for i := range idx.Releases {
			if idx.Releases[i].Version == version {
				rel = &idx.Releases[i]
				break
			}
		}
	}
	if rel == nil {
		return fmt.Errorf("no applicable release found in the channel")
	}
	path, err := s.download(ctx, rel.BundleURL)
	if err != nil {
		return fmt.Errorf("download bundle: %w", err)
	}
	// Apply verifies the downloaded bundle's own signature before doing anything.
	return s.Apply(ctx, path, actorName)
}

// download streams a bundle from url into the staging path with a size cap.
func (s *Service) download(ctx context.Context, url string) (string, error) {
	if err := os.MkdirAll(s.cfg.UpdatesDir, 0o700); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	// The bundle download can be large; use a dedicated client without the short
	// timeout the status/updater calls use.
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d fetching bundle", resp.StatusCode)
	}
	path := s.stagedPath()
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(f, io.LimitReader(resp.Body, maxBundleDownload)); err != nil {
		return "", err
	}
	return path, nil
}

// maxBundleDownload caps a pulled bundle (image bundles are large but bounded).
const maxBundleDownload = 4 << 30 // 4 GiB

func (s *Service) updaterStatus(ctx context.Context) (Status, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.UpdaterURL+"/status", nil)
	if err != nil {
		return Status{}, false
	}
	if s.cfg.UpdaterToken != "" {
		req.Header.Set("X-Updater-Token", s.cfg.UpdaterToken)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return Status{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Status{}, false
	}
	var us Status
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&us); err != nil {
		return Status{}, false
	}
	return us, true
}
