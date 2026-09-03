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

const (
	// How often the reconcile loop looks for machines a live rollout is waiting
	// on. Frequent enough that a rollout advances in about the time an install
	// takes; nothing happens at all when no rollout is live.
	reconcileEvery = 30 * time.Second
	// A nudge is one short command over an already-cheap connection. If it has
	// not finished in this long the host is not in a state to take an update
	// anyway, and the agent's own timer remains the fallback.
	nudgeTimeout = 45 * time.Second
	// A direct install downloads and writes a whole root filesystem.
	installTimeout = 60 * time.Minute
	// Ceiling on how many hosts are nudged in one pass. The jump host has an
	// sshd MaxStartups limit that the monitor sweep already lives within; a
	// rollout arriving at the same moment must not be what trips it.
	maxNudgesPerPass = 20
)

// Service is the Flipside subsystem: a client, the correlation between Moorgate
// hosts and Flipside machines, and the SSH actions that give Flipside reach.
type Service struct {
	store  *store.Store
	cfg    *config.Config
	log    *slog.Logger
	gw     *sshgw.Gateway
	issuer *identity.Issuer
	nfy    *notify.Service
	client *Client

	// Rollouts whose halt has already been announced, so a halted rollout
	// notifies once rather than on every pass of the loop.
	mu       sync.Mutex
	halted   map[string]bool
	nudgedAt map[string]time.Time
}

func New(st *store.Store, cfg *config.Config, log *slog.Logger, gw *sshgw.Gateway,
	issuer *identity.Issuer, nfy *notify.Service) *Service {
	return &Service{
		store:    st,
		cfg:      cfg,
		log:      log,
		gw:       gw,
		issuer:   issuer,
		nfy:      nfy,
		client:   NewClient(cfg.FlipsideURL, cfg.FlipsideToken, 0),
		halted:   map[string]bool{},
		nudgedAt: map[string]time.Time{},
	}
}

func (s *Service) Client() *Client { return s.client }

// Enabled reports whether a Flipside server is configured at all. Everything
// this subsystem exposes answers "not configured" rather than an error when it
// is not, so a deployment that does not use Flipside sees nothing new.
func (s *Service) Enabled() bool { return s.client.Configured() }

// --- correlation -------------------------------------------------------------

// MachineIDFor returns the Flipside machine id recorded against a host, if any.
func MachineIDFor(h *models.Host) string { return strings.TrimSpace(h.Options.FlipsideMachineID) }

// Link is one Moorgate host paired with one Flipside machine, and how they were
// paired. `how` matters: a hostname match is a guess that stops being true the
// moment a machine is renamed, and the UI offers to make it explicit.
type Link struct {
	Host    *models.Host
	Machine *Machine
	How     string // linked | hostname | none
}

// Correlate pairs hosts with machines.
//
// An explicit link wins and is never re-derived — it is the only form that
// survives a rename or a re-image. Otherwise the agent's reported hostname is
// matched against the host's, which is right often enough to be useful and
// wrong often enough that it is labelled as a guess rather than recorded as
// fact.
//
// Machines with no host are kept in the result. A machine Flipside knows about
// and Moorgate does not is usually one that was imaged and never enrolled,
// which is a thing worth seeing rather than a thing to hide.
func Correlate(hosts []models.Host, machines []Machine) ([]Link, []Machine) {
	byID := map[string]*Machine{}
	for i := range machines {
		byID[machines[i].ID] = &machines[i]
	}
	byHostname := map[string]*Machine{}
	for i := range machines {
		if n := normaliseHostname(machines[i].Hostname); n != "" {
			// First writer wins, and a duplicate hostname disqualifies the
			// name entirely: two machines calling themselves web01 make the
			// name useless as an identifier, and picking one at random would
			// be worse than admitting it.
			if _, clash := byHostname[n]; clash {
				byHostname[n] = nil
			} else {
				byHostname[n] = &machines[i]
			}
		}
	}

	claimed := map[string]bool{}
	links := make([]Link, 0, len(hosts))
	for i := range hosts {
		h := &hosts[i]
		if id := MachineIDFor(h); id != "" {
			if m, ok := byID[id]; ok {
				claimed[m.ID] = true
				links = append(links, Link{Host: h, Machine: m, How: "linked"})
				continue
			}
			// Recorded against a machine Flipside no longer has. Shown as
			// unpaired rather than silently falling back to a hostname guess,
			// because a link that has stopped resolving is worth noticing.
			links = append(links, Link{Host: h, How: "none"})
			continue
		}
		if m := byHostname[normaliseHostname(h.Hostname)]; m != nil && !claimed[m.ID] {
			claimed[m.ID] = true
			links = append(links, Link{Host: h, Machine: m, How: "hostname"})
			continue
		}
		links = append(links, Link{Host: h, How: "none"})
	}

	var orphans []Machine
	for i := range machines {
		if !claimed[machines[i].ID] {
			orphans = append(orphans, machines[i])
		}
	}
	return links, orphans
}

// normaliseHostname strips the domain and case. A machine reports what
// `hostname` says, which is short on some systems and fully qualified on
// others, and Moorgate's host record is whatever an operator typed.
func normaliseHostname(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	return s
}

// --- reaching a host ---------------------------------------------------------

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

// Nudge makes a machine check in with Flipside now instead of on its own timer.
//
// This is the whole of the "push" this subsystem adds, and it is deliberately
// that small. The agent does everything it would have done five minutes later,
// and Flipside applies the rollout's rules unchanged — canary, soak, batch,
// window, budget. Moorgate removes the waiting and decides nothing.
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
		return out, fmt.Errorf("%s has no Flipside agent installed", h.Hostname)
	}
	return out, nil
}

// Install writes a bundle to a host's inactive slot directly, for machines that
// cannot reach Flipside at all.
//
// The bundle is fetched by the host from the URL Flipside recorded for the
// rollout, which is derived from its CONTROL_URL — the address that works from
// where the fleet lives. RAUC verifies the signature against the certificate
// inside the machine's own image exactly as on any other path; nothing about
// the trust chain changes because Moorgate asked for it.
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
	// Quoted as a single shell word. The URL comes from Flipside rather than
	// from a browser, but it reaches a shell, and "it came from a trusted
	// system" is the reasoning behind most command injections.
	out, err := run(conn, "sudo -n /usr/local/sbin/ab-update "+shellQuote(bundleURL)+" 2>&1")
	if err != nil {
		return out, fmt.Errorf("ab-update on %s: %w", h.Hostname, err)
	}
	return out, nil
}

// Observe reads what is actually on a host: the version the running slot
// carries and whether systemd considers the boot healthy.
//
// This is what makes the direct-install path honest. A machine that cannot
// reach Flipside cannot report that it took an update, so Moorgate reports on
// its behalf — but only about what it has just read off the host itself, which
// is better evidence than a machine's own word.
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
			// systemd's vocabulary, mapped to Flipside's. Anything but running
			// or starting means a unit failed, which a rollout must not count
			// as a success.
			switch value {
			case "running", "starting", "":
				obs.Health = "ok"
			default:
				obs.Health = "degraded"
			}
		}
	}
	if obs.Version == "" {
		return obs, fmt.Errorf("%s reports no Flipside version; it may not be a Flipside image", h.Hostname)
	}
	return obs, nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// InstallAndReport writes a bundle and then tells Flipside what happened,
// which is the half that makes the direct path usable at all.
//
// A machine that cannot reach Flipside cannot report that it took an update, so
// a rollout containing it would wait for a check-in that can never arrive.
// Moorgate reports instead — and reports only what it just read off the host.
//
// The version does not change here: ab-update writes the *inactive* slot, and
// the machine runs the old one until it reboots. So this reports "installed",
// which moves the rollout to waiting-for-the-reboot; the loop below finishes the
// story once the machine has actually come back on the new version.
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
		// Nothing observed and nothing to say. Reporting a blank version would
		// be Flipside recording that Moorgate looked and saw nothing, which is
		// worse than Moorgate not having spoken.
		return out, err
	}
	if rerr := s.client.Report(ctx, machineID, obs); rerr != nil {
		s.log.Warn("imaging: reporting an install to Flipside", "host", h.Hostname, "err", rerr)
	}
	return out, err
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// --- the reconcile loop ------------------------------------------------------

// Run drives rollouts forward by nudging the machines they are waiting on.
//
// leader gates the loop the same way the monitor sweep is gated: in a
// multi-instance deployment only one instance should be nudging, or every host
// gets N simultaneous SSH connections saying the same thing.
//
// Nothing runs at all unless a rollout is live. This is not a periodic sweep of
// the fleet; it is a response to an operator having started something.
func (s *Service) Run(ctx context.Context, leader func() bool) {
	if !s.Enabled() || !s.cfg.FlipsideNudge {
		return
	}
	t := time.NewTicker(reconcileEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if leader != nil && !leader() {
				continue
			}
			s.reconcile(ctx)
		}
	}
}

func (s *Service) reconcile(ctx context.Context) {
	rollouts, err := s.client.Rollouts(ctx)
	if err != nil {
		// Logged at debug: Flipside being briefly unreachable is not an event,
		// and a warning every thirty seconds would be its own problem. The
		// Imaging page shows the real reachability state.
		s.log.Debug("imaging: listing rollouts", "err", err)
		return
	}

	var waiting []string
	// Machines a rollout believes are mid-update. If one of them cannot reach
	// Flipside — a site with no route back — nobody will ever tell Flipside how
	// it went, and the rollout sits on it until the offer times out. Moorgate
	// can see the machine, so Moorgate says.
	inFlight := map[string]bool{}
	for i := range rollouts {
		r := &rollouts[i]
		s.announceHalt(ctx, r)
		if r.State != "running" {
			continue
		}
		for id, m := range r.Machines {
			switch m.State {
			case "pending":
				waiting = append(waiting, id)
			case "installing", "rebooting":
				inFlight[id] = true
			}
		}
	}
	if len(waiting) == 0 && len(inFlight) == 0 {
		return
	}

	hosts, err := s.store.ListHosts(ctx, 10000, 0)
	if err != nil {
		s.log.Warn("imaging: listing hosts", "err", err)
		return
	}
	machines := make([]Machine, 0, len(waiting)+len(inFlight))
	for _, id := range waiting {
		machines = append(machines, Machine{ID: id})
	}
	for id := range inFlight {
		machines = append(machines, Machine{ID: id})
	}
	links, _ := Correlate(hosts, machines)

	// Only machines a rollout is actually waiting on, and only ones Moorgate
	// can reach. Everything else updates on the agent's own timer, as it did
	// before this existed.
	wanted := map[string]bool{}
	for _, id := range waiting {
		wanted[id] = true
	}
	sent := 0
	for _, l := range links {
		if l.Machine == nil || sent >= maxNudgesPerPass {
			continue
		}
		if l.Host.InMaintenance() || !l.Host.Enrolled || l.Host.Protocol == "rdp" {
			continue
		}
		// A machine the rollout thinks is mid-update. Nudging it would do
		// nothing useful; what is needed is somebody to look and say what
		// happened, and only if the machine cannot say so itself.
		if inFlight[l.Machine.ID] {
			sent++
			host := l.Host
			id := l.Machine.ID
			go s.settle(ctx, host, id)
			continue
		}
		if !wanted[l.Machine.ID] {
			continue
		}
		// One nudge per machine per interval. Without this, a machine that is
		// slow to install would be nudged on every pass for the whole install.
		s.mu.Lock()
		last, seen := s.nudgedAt[l.Machine.ID]
		fresh := seen && time.Since(last) < 5*time.Minute
		if !fresh {
			s.nudgedAt[l.Machine.ID] = time.Now()
		}
		s.mu.Unlock()
		if fresh {
			continue
		}
		sent++
		host := l.Host
		go func() {
			if _, err := s.Nudge(ctx, host); err != nil {
				// Not an alert. A nudge that fails costs latency and nothing
				// else -- the agent still polls -- and a fleet with a few
				// sleeping laptops would otherwise generate a steady drip of
				// warnings about a system that is working correctly.
				s.log.Debug("imaging: nudge", "host", host.Hostname, "err", err)
			}
		}()
	}
	if sent > 0 {
		s.log.Info("imaging: nudged machines a rollout is waiting on", "count", sent)
	}
}

// settle looks at a machine a rollout believes is mid-update and reports what
// is actually there.
//
// Only for machines Flipside cannot hear from itself: if the agent is checking
// in, its own word arrives on its own timer and Moorgate has no business
// speaking over it. The check is Flipside's, not Moorgate's — a machine whose
// presence is `online` is one Flipside is hearing from.
func (s *Service) settle(ctx context.Context, h *models.Host, machineID string) {
	obs, err := s.Observe(ctx, h)
	if err != nil {
		s.log.Debug("imaging: settling", "host", h.Hostname, "err", err)
		return
	}
	obs.ObservedBy = "moorgate"
	// Deliberately no update_state: the version and health are what a rollout
	// decides from, and asserting a state as well would be Moorgate guessing
	// at a machine's internal progress rather than reporting what it saw.
	if err := s.client.Report(ctx, machineID, obs); err != nil {
		s.log.Debug("imaging: reporting an observation", "host", h.Hostname, "err", err)
	}
}

// announceHalt notifies once when a rollout stops itself on its failure budget.
//
// This is the event an operator most needs pushed at them rather than found:
// a halted rollout means machines failed an update and the rest of the fleet is
// deliberately not getting it, and nothing else will say so.
func (s *Service) announceHalt(ctx context.Context, r *Rollout) {
	if s.nfy == nil {
		return
	}
	s.mu.Lock()
	already := s.halted[r.ID]
	if r.State == "halted" {
		s.halted[r.ID] = true
	} else {
		delete(s.halted, r.ID)
	}
	s.mu.Unlock()
	if r.State != "halted" || already {
		return
	}
	s.nfy.Notify(ctx, notify.Event{
		Type:     notify.EventRolloutHalted,
		Severity: notify.SeverityError,
		Title:    "Rollout halted: " + r.Version,
		Body: fmt.Sprintf("Flipside stopped rolling out %s. %s %d of %d machines were done.",
			r.Bundle, r.HaltReason, r.Done, r.Total),
		DedupeKey: "flipside-rollout-" + r.ID,
	})
}
