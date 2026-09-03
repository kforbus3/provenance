package imaging

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kforbus3/Moorgate/backend/internal/config"
	"github.com/kforbus3/Moorgate/backend/internal/identity"
	"github.com/kforbus3/Moorgate/backend/internal/models"
	"github.com/kforbus3/Moorgate/backend/internal/notify"
	"github.com/kforbus3/Moorgate/backend/internal/sshgw"
	"github.com/kforbus3/Moorgate/backend/internal/store"
)

// Service is the imaging subsystem: the machine records, the rollout engine,
// and the SSH actions that let this server reach a machine rather than wait for
// it to ask.
//
// Reaching machines is the whole reason the imager and the fleet manager are one
// program. On its own the imaging control plane has to be a pull: a machine is
// imaged on a private provisioning switch and then moved to wherever it lives,
// so the imaging server never learns its address and usually cannot route to it.
// An operator could therefore start a rollout and then only wait.
//
// The same server already reaches every enrolled host through the jump host. So
// the pull stays -- it is what makes a rollout work at all for a machine behind
// a firewall nobody controls -- and reaching out becomes the fast path on top of
// it:
//
//	nudge     `ab-agent --now` over the gateway. The agent does exactly what it
//	          would have done minutes later; the rollout's rules are unchanged.
//	          A failed nudge costs latency, not the update -- the agent polls.
//	install   `ab-update` over SSH, for machines with no route back at all.
//	observe   read the version and health off the host, so a machine that
//	          cannot report for itself still advances its rollout.
type Service struct {
	store  *store.Store
	cfg    *config.Config
	log    *slog.Logger
	gw     *sshgw.Gateway
	issuer *identity.Issuer
	nfy    *notify.Service

	// Live progress of machines being imaged right now. In memory on purpose;
	// see progress.go.
	progress *progressRegistry

	// Rollouts whose halt has already been announced, so a halted rollout
	// notifies once rather than on every pass of the loop.
	mu      sync.Mutex
	halted  map[string]bool
	touched map[string]time.Time
}

// timeNow exists so imagerhandlers.go reads the clock through one name rather
// than reaching for time.Now() in the middle of building a record.
func timeNow() time.Time { return time.Now() }

func New(st *store.Store, cfg *config.Config, log *slog.Logger, gw *sshgw.Gateway,
	issuer *identity.Issuer, nfy *notify.Service) *Service {
	return &Service{
		store: st, cfg: cfg, log: log, gw: gw, issuer: issuer, nfy: nfy,
		progress: newProgressRegistry(),
		halted:   map[string]bool{},
		touched:  map[string]time.Time{},
	}
}

// AgentInterval is how often a machine's agent checks in. Sent back in every
// reply, so changing it re-paces the whole fleet without touching a machine.
func (s *Service) AgentInterval() time.Duration {
	if s.cfg.AgentInterval > 0 {
		return time.Duration(s.cfg.AgentInterval) * time.Second
	}
	return 5 * time.Minute
}

const (
	// A nudge is one short command over an already-cheap connection. If it has
	// not finished in this long the host is not in a state to take an update
	// anyway, and the agent's own timer remains the fallback.
	nudgeTimeout = 45 * time.Second
	// A direct install downloads and writes a whole root filesystem.
	installTimeout = 60 * time.Minute
	// How often the reconcile loop looks for machines a live rollout is waiting
	// on. Nothing happens at all when no rollout is live.
	reconcileEvery = 30 * time.Second
	// Ceiling per pass. The jump host has an sshd MaxStartups limit the monitor
	// sweep already lives within; a rollout must not be what trips it.
	maxActionsPerPass = 20
)

// Observation is what was seen on a host, over SSH, directly.
type Observation struct {
	Version     string
	Health      string
	Slot        string
	UpdateState string
	UpdateError string
	ObservedBy  string
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\u2026"
}

// dial opens a connection to a host through the jump host, exactly as the
// monitor sweep does: a system certificate scoped to that host, tried against
// the overlay address first and then whatever else the host record knows.
func (s *Service) dial(ctx context.Context, h *models.Host) (*sshgw.Conn, error) {
	signer, err := s.issuer.SystemSigner(ctx, s.issuer.SystemHostPrincipals(h.ID), time.Hour)
	if err != nil {
		return nil, fmt.Errorf("issuing a certificate for %s: %w", h.Hostname, err)
	}
	var last error
	for _, addr := range dedupe([]string{h.WGAddress, h.Address, h.Hostname}) {
		conn, derr := s.gw.DialWithSigner(ctx, signer, addr, h.SSHPort, h.SSHUser)
		if derr == nil {
			return conn, nil
		}
		last = derr
	}
	if last == nil {
		last = fmt.Errorf("no address recorded for %s", h.Hostname)
	}
	return nil, fmt.Errorf("reaching %s: %w", h.Hostname, last)
}

func run(conn *sshgw.Conn, cmd string) (string, error) {
	sess, err := conn.Client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	return string(out), err
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// Nudge makes a machine check in now instead of on its own timer.
//
// This is the whole of the "push", and it is deliberately that small. The agent
// does everything it would have done five minutes later, and the rollout engine
// applies its rules unchanged -- canary, soak, batch, window, budget. Reaching
// the machine removes the waiting and decides nothing, which is what keeps one
// set of rules governing a rollout however it was started.
//
// A failure is not an error worth escalating: the agent's timer is still there,
// so a host that could not be reached updates late rather than not at all.
func (s *Service) Nudge(ctx context.Context, h *models.Host) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, nudgeTimeout)
	defer cancel()
	conn, err := s.dial(ctx, h)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	out, err := run(conn, "sudo -n /usr/local/sbin/ab-agent --now 2>&1 || /usr/local/sbin/ab-agent --now 2>&1")
	if err != nil && strings.TrimSpace(out) == "" {
		return "", fmt.Errorf("running ab-agent on %s: %w", h.Hostname, err)
	}
	if strings.Contains(out, "not found") || strings.Contains(out, "No such file") {
		return out, fmt.Errorf("%s has no update agent installed; it is probably not "+
			"a machine this server imaged", h.Hostname)
	}
	return out, nil
}

// Install writes a bundle to a host's inactive slot directly, for machines that
// cannot reach this server at all.
//
// The host still fetches the bundle itself, from the URL recorded on the rollout
// -- derived from CONTROL_URL, the address that works from where the fleet
// lives rather than from where this server sits. RAUC verifies the signature
// against the certificate baked into the machine's own image exactly as on every
// other path. An operator asking for an install does not become a reason to
// trust a bundle; nothing about the chain changes because the request came from
// inside.
func (s *Service) Install(ctx context.Context, h *models.Host, bundleURL string) (string, error) {
	if !strings.HasPrefix(bundleURL, "http://") && !strings.HasPrefix(bundleURL, "https://") {
		return "", fmt.Errorf("refusing a bundle URL that is not http(s): %q", bundleURL)
	}
	ctx, cancel := context.WithTimeout(ctx, installTimeout)
	defer cancel()
	conn, err := s.dial(ctx, h)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	// Quoted as a single shell word. This URL was built by this server rather
	// than typed into a browser, but it still reaches a shell, and "it came from
	// a trusted system" is the reasoning behind most command injections.
	out, err := run(conn, "sudo -n /usr/local/sbin/ab-update "+shellQuote(bundleURL)+" 2>&1")
	if err != nil {
		return out, fmt.Errorf("ab-update on %s: %w", h.Hostname, err)
	}
	return out, nil
}

// Observe reads what is actually on a host: the version the running slot
// carries and whether systemd considers the boot healthy.
//
// This is what makes the direct-install path honest. A machine that cannot reach
// this server cannot report that it took an update, so the server files a report
// on its behalf -- but only about what it has just read off the host, which is
// better evidence than the machine's own word, not worse.
func (s *Service) Observe(ctx context.Context, h *models.Host) (Observation, error) {
	ctx, cancel := context.WithTimeout(ctx, nudgeTimeout)
	defer cancel()
	conn, err := s.dial(ctx, h)
	if err != nil {
		return Observation{}, err
	}
	defer conn.Close()
	// One command, because each session costs a round trip through the jump
	// host and there is nothing here that needs to be separable.
	out, _ := run(conn, `slot=$(sed -n 's/.*rauc\.slot=\([AB]\).*/\1/p' /proc/cmdline 2>/dev/null); `+
		`echo "slot=$slot"; `+
		`if [ -n "$slot" ] && [ -r "/boot/$slot/ab-version" ]; then echo "version=$(cat /boot/$slot/ab-version)"; `+
		// The fallback path is /usr/lib/flipside/version, not a name matching this
		// product. It is compiled into every image already in the field, and
		// renaming it would make this server unable to read a version off any
		// machine imaged before the rename -- for a cosmetic gain.
		`elif [ -r /usr/lib/flipside/version ]; then echo "version=$(cat /usr/lib/flipside/version)"; fi; `+
		`echo "health=$(systemctl is-system-running 2>/dev/null)"`)
	obs := Observation{}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "slot":
			obs.Slot = value
		case "version":
			obs.Version = value
		case "health":
			// systemd's vocabulary, mapped to the rollout engine's. Anything but
			// running or starting means a unit failed, which a rollout must not
			// count as a success.
			switch value {
			case "running", "starting", "":
				obs.Health = "ok"
			default:
				obs.Health = "degraded"
			}
		}
	}
	if obs.Version == "" {
		return obs, fmt.Errorf("%s reports no image version; it may not be running an "+
			"A/B image from this server", h.Hostname)
	}
	return obs, nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// InstallAndReport writes a bundle to a host and then records what was actually
// on it afterwards.
//
// A machine that cannot reach this server cannot report that it took an update,
// so a rollout containing it would wait for a check-in that can never arrive.
// This reports instead -- and only what was just read off the host.
//
// The version does not change here: ab-update writes the *inactive* slot, and
// the machine runs the old one until it reboots. So this records "installed",
// which moves the rollout to waiting-for-the-reboot; the reconcile loop finishes
// the story once the machine has come back on the new version.
func (s *Service) InstallAndReport(ctx context.Context, h *models.Host, machineID, bundleURL, by string) (string, error) {
	out, err := s.Install(ctx, h, bundleURL)
	if machineID == "" {
		return out, err
	}
	obs, oerr := s.Observe(ctx, h)
	obs.ObservedBy = by
	if err != nil {
		obs.UpdateState = "failed"
		obs.UpdateError = trunc(err.Error(), 200)
	} else {
		obs.UpdateState = "installed"
	}
	if oerr != nil && obs.Version == "" {
		// Nothing observed and nothing to say. Recording a blank version would
		// be this server noting that it looked and saw nothing, which is worse
		// than not having spoken.
		return out, err
	}
	s.recordObservation(ctx, machineID, obs)
	return out, err
}

// recordObservation files what was seen on a host, and lets the rollout act on
// it exactly as it would on the machine's own check-in.
//
// Marked as observed rather than as an agent report. That difference is kept
// because it is real: a machine's word about itself and something else's word
// about the machine are different evidence, and when one turns out to be wrong
// the fleet's history should say which kind it was.
func (s *Service) recordObservation(ctx context.Context, machineID string, obs Observation) {
	m := &models.ImagingMachine{
		ID: machineID, Version: obs.Version, Health: obs.Health, Slot: obs.Slot,
		UpdateState: obs.UpdateState, UpdateError: obs.UpdateError,
		ReportedBy: obs.ObservedBy, ReportSource: "observed",
	}
	if _, err := s.store.ReportMachine(ctx, m); err != nil {
		s.log.Warn("imaging: recording an observation", "machine", machineID, "err", err)
		return
	}
	s.EvaluateFor(ctx, machineID, Report{
		Version: obs.Version, Health: obs.Health,
		UpdateState: obs.UpdateState, UpdateError: obs.UpdateError,
	})
}
