// Package netscan runs network vulnerability scans: the half of vulnerability
// scanning grype cannot see. grype (internal/vulnscan) reads a host's package
// database and reports what is installed and vulnerable; this asks the network what
// the host exposes -- which ports answer, from which path, what is serving on them,
// and whether that service is vulnerable or misconfigured.
//
// The scanning itself happens in the net-scanner sidecar (deploy/net-scanner). This
// package decides what to scan and from where, collects the host's own listener list
// to compare against, records the results, and joins them to grype's findings.
package netscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/kforbus3/provenance/backend/internal/config"
	"github.com/kforbus3/provenance/backend/internal/credinject"
	"github.com/kforbus3/provenance/backend/internal/identity"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/notify"
	"github.com/kforbus3/provenance/backend/internal/sshgw"
	"github.com/kforbus3/provenance/backend/internal/store"
	"github.com/kforbus3/provenance/backend/internal/winrm"
)

// Service runs network scans.
type Service struct {
	store  *store.Store
	cfg    *config.Config
	log    *slog.Logger
	gw     *sshgw.Gateway
	issuer *identity.Issuer
	nfy    *notify.Service
	sc     *sidecar
	// resolve turns a host's address or name into an IP literal. A field so tests
	// can plan paths without DNS.
	resolve func(ctx context.Context, name string) (string, error)
}

// New constructs the service.
func New(st *store.Store, cfg *config.Config, log *slog.Logger, gw *sshgw.Gateway,
	issuer *identity.Issuer, nfy *notify.Service) *Service {
	return &Service{
		store: st, cfg: cfg, log: log, gw: gw, issuer: issuer, nfy: nfy,
		sc: &sidecar{url: strings.TrimRight(cfg.NetScanURL, "/"), token: cfg.NetScanToken,
			client: &http.Client{Timeout: cfg.NetScanTimeout}},
		resolve: resolveIP,
	}
}

// Configured reports whether the token is set. Without it nothing can be scanned.
func (s *Service) Configured() bool { return s.sc.token != "" }

func resolveIP(ctx context.Context, name string) (string, error) {
	name = strings.Trim(strings.TrimSpace(name), "[]")
	if ip := net.ParseIP(name); ip != nil {
		return ip.String(), nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, name)
	if err != nil {
		return "", err
	}
	// IPv4 first: it is what the overlay and almost every managed network use.
	for _, ip := range ips {
		if v4 := ip.IP.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	if len(ips) > 0 {
		return ips[0].IP.String(), nil
	}
	return "", fmt.Errorf("no addresses for %q", name)
}

// target is one address a host is to be scanned at.
type target struct {
	Path string
	Addr string
	// Unreachable, when set, is why this path cannot be scanned at all; the scan is
	// recorded as unreachable with this reason rather than silently skipped, so a
	// host never reads as covered on a path nothing looked at.
	Unreachable string
}

// overlayState is what the scanner can reach on the overlay.
//
// skip and a failed route are different things. skip: this deployment does not put
// the scanner where the overlay is reachable (Kubernetes, an external jump host) --
// a property of the deployment, reported once as a warning, not as a failure on
// every host every night. Otherwise, a scanner that should reach the overlay and
// cannot is a real failure, recorded per host.
type overlayState struct {
	ok   bool
	skip bool
	why  string
}

// planPaths decides where a host is scanned from: its LAN address and its overlay
// address, each once. Pure apart from resolve, so the decisions are testable.
func planPaths(ctx context.Context, h *models.Host, resolve func(context.Context, string) (string, error),
	ov overlayState) []target {
	var out []target

	overlayIP := ""
	if h.WGAddress != "" && h.Enrolled {
		overlayIP = strings.TrimSpace(h.WGAddress)
		// ov.skip: not scanned, and not a failure either; see overlayState.
		switch {
		case ov.ok:
			out = append(out, target{Path: models.NetPathOverlay, Addr: overlayIP})
		case !ov.skip:
			out = append(out, target{Path: models.NetPathOverlay, Addr: overlayIP, Unreachable: ov.why})
		}
	}

	lan := strings.TrimSpace(h.Address)
	if lan == "" {
		lan = strings.TrimSpace(h.Hostname)
	}
	switch {
	case lan == "":
		out = append(out, target{Path: models.NetPathLAN, Unreachable: "the host has no address or hostname to scan"})
	default:
		ip, err := resolve(ctx, lan)
		switch {
		case err != nil:
			out = append(out, target{Path: models.NetPathLAN, Addr: lan,
				Unreachable: fmt.Sprintf("could not resolve %q: %v", lan, err)})
		case ip == overlayIP:
			// The host's only address IS its overlay address; one scan covers it.
		default:
			out = append(out, target{Path: models.NetPathLAN, Addr: ip})
		}
	}
	// LAN first: it is what most readers mean by "this host".
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path == models.NetPathLAN && out[j].Path != models.NetPathLAN })
	return out
}

// jumpAddrs are the jump host's addresses, which scans skip by default.
func (s *Service) jumpAddrs(ctx context.Context) map[string]bool {
	m := map[string]bool{}
	for _, a := range []string{s.cfg.WGJumpIP, s.cfg.OVPNJumpIP} {
		if a = strings.TrimSpace(a); a != "" {
			m[a] = true
		}
	}
	if hostPart, _, err := net.SplitHostPort(s.cfg.JumpHost); err == nil && hostPart != "" {
		m[hostPart] = true
		if ip, err := s.resolve(ctx, hostPart); err == nil {
			m[ip] = true
		}
	}
	return m
}

func (s *Service) isJumpHost(ctx context.Context, h *models.Host, jump map[string]bool) bool {
	if s.cfg.NetScanIncludeJumpHost {
		return false
	}
	for _, a := range []string{h.Address, h.WGAddress, h.Hostname} {
		if a = strings.TrimSpace(a); a != "" && jump[a] {
			return true
		}
	}
	if h.Address != "" {
		if ip, err := s.resolve(ctx, h.Address); err == nil && jump[ip] {
			return true
		}
	}
	return false
}

func (s *Service) overlay(ctx context.Context) overlayState {
	h, err := s.sc.health(ctx)
	if err != nil {
		return overlayState{why: "the network scanner's health could not be read: " + err.Error()}
	}
	switch h.Overlay {
	case "ok":
		return overlayState{ok: true}
	case "not-configured":
		return overlayState{skip: true, why: "Overlay address not scanned: the network scanner does not run " +
			"in the jump host's network namespace in this deployment, so overlay addresses cannot be reached " +
			"from it (the single-server layout, docker-compose.jumphost.yml, places it there)."}
	default:
		return overlayState{why: "the network scanner has no route to the overlay. If the jump host was " +
			"recreated, restart the net-scanner container so it rejoins the jump host's network namespace."}
	}
}

// Started is one host whose scan rows were created.
type Started struct {
	HostID   uuid.UUID   `json:"hostId"`
	Hostname string      `json:"hostname"`
	RunID    uuid.UUID   `json:"runId"`
	ScanIDs  []uuid.UUID `json:"scanIds"`
}

// Skipped is a host that was not scanned, and why.
type Skipped struct {
	HostID   uuid.UUID `json:"hostId"`
	Hostname string    `json:"hostname"`
	Reason   string    `json:"reason"`
}

// hostSem bounds hosts scanned at once across every caller. The sidecar has its own
// (smaller) concurrency; this keeps the backend from holding hundreds of idle
// requests and SSH sessions open against it.
var hostSem = make(chan struct{}, 4)

// StartHosts creates scan rows for each host's paths on reqCtx (so the caller gets
// ids back), then scans in the background on bg. bg must carry the tenant (see
// auth.TenantScope) -- the rows are written under it. wait blocks until every scan
// started here has finished.
func (s *Service) StartHosts(reqCtx, bg context.Context, hosts []*models.Host, by *uuid.UUID,
	requester string, scheduled bool) (started []Started, skipped []Skipped, wait func(), err error) {
	if !s.Configured() {
		return nil, nil, func() {}, ErrNotConfigured
	}
	ov := s.overlay(reqCtx)
	jump := s.jumpAddrs(reqCtx)
	var wg sync.WaitGroup
	for _, h := range hosts {
		if s.isJumpHost(reqCtx, h, jump) {
			skipped = append(skipped, Skipped{HostID: h.ID, Hostname: h.Hostname,
				Reason: "the jump host is excluded from network scans (PROV_NETSCAN_INCLUDE_JUMPHOST)"})
			continue
		}
		plan := planPaths(reqCtx, h, s.resolve, ov)
		var planWarn string
		if ov.skip && h.WGAddress != "" && h.Enrolled {
			planWarn = ov.why
		}
		runID := uuid.New()
		st := Started{HostID: h.ID, Hostname: h.Hostname, RunID: runID}
		var rows []row
		for _, t := range plan {
			hid := h.ID
			addr := t.Addr
			if addr == "" {
				addr = "-"
			}
			id, cerr := s.store.CreateNetScan(reqCtx, runID, &hid, nil, addr, t.Path, by, requester, scheduled)
			if cerr != nil {
				s.log.Warn("netscan: create scan", "host", h.Hostname, "err", cerr)
				continue
			}
			st.ScanIDs = append(st.ScanIDs, id)
			rows = append(rows, row{id: id, t: t, warn: planWarn})
		}
		if len(rows) == 0 {
			skipped = append(skipped, Skipped{HostID: h.ID, Hostname: h.Hostname, Reason: "could not record a scan"})
			continue
		}
		started = append(started, st)
		wg.Add(1)
		go func(h *models.Host, rows []row) {
			defer wg.Done()
			hostSem <- struct{}{}
			defer func() { <-hostSem }()
			s.runHost(bg, h, rows)
		}(h, rows)
	}
	return started, skipped, wg.Wait, nil
}

type row struct {
	id   uuid.UUID
	t    target
	warn string // a planning note carried onto the scan (e.g. the overlay was not scanned)
}

func (s *Service) runHost(ctx context.Context, h *models.Host, rows []row) {
	for _, r := range rows {
		if err := s.store.StartNetScan(ctx, r.id); err != nil {
			s.log.Warn("netscan: start", "host", h.Hostname, "err", err)
		}
	}
	listeners, lwarn := s.collectListeners(ctx, h)
	for _, r := range rows {
		s.scanOne(ctx, r, h, listeners, lwarn, probePorts(h))
	}
}

// probePorts are the ports used to tell "up, nothing reachable" from "unreachable"
// when the sweep finds nothing open: ones the host is known to answer on.
func probePorts(h *models.Host) []int {
	if h == nil {
		return nil
	}
	if h.Protocol == "rdp" {
		return []int{3389, 5986, 5985, 445}
	}
	p := h.SSHPort
	if p <= 0 {
		p = 22
	}
	return []int{p, 22, 443, 80}
}

func (s *Service) scanOne(ctx context.Context, r row, h *models.Host, listeners []models.NetListener,
	lwarn string, probe []int) {
	label := r.t.Addr
	if h != nil {
		label = h.Hostname
	}
	if r.t.Unreachable != "" {
		s.complete(ctx, r.id, store.NetScanResult{Status: models.NetScanUnreachable, Reason: r.t.Unreachable,
			Listeners: listeners}, label, r.t.Path)
		return
	}
	sctx, cancel := context.WithTimeout(ctx, s.cfg.NetScanTimeout+time.Minute)
	defer cancel()
	req := scanRequest{Target: r.t.Addr, TCPPorts: "full", UDP: true, AliveProbePorts: probe}
	// A managed host is a server that can take a brisker rate; at the sidecar's
	// default, a host serving six web ports took 15 minutes per path. Range
	// addresses (h == nil) keep the default.
	if h != nil {
		req.NucleiRate = s.cfg.NetScanHostRate
	}
	res, err := s.sc.scan(sctx, req)
	if err != nil {
		s.log.Warn("netscan failed", "target", label, "path", r.t.Path, "err", err)
		if ferr := s.store.FailNetScan(ctx, r.id, err.Error()); ferr != nil {
			s.log.Warn("netscan: record failure", "target", label, "err", ferr)
		}
		return
	}
	if !res.Reachable {
		reason := res.Reason
		if r.t.Path == models.NetPathOverlay {
			reason += ". On the overlay this usually means the host's tunnel is down right now."
		}
		s.complete(ctx, r.id, store.NetScanResult{Status: models.NetScanUnreachable, Reason: reason,
			TemplatesVersion: res.templatesVersion(), Listeners: listeners, DurationSec: res.DurationSec}, label, r.t.Path)
		return
	}
	services, findings := merge(res, listeners)
	var warnings []string
	if r.warn != "" {
		warnings = append(warnings, r.warn)
	}
	if lwarn != "" {
		warnings = append(warnings, lwarn)
	}
	if w := unexpectedWarning(services); w != "" {
		warnings = append(warnings, w)
	}
	for _, e := range res.Errors {
		warnings = append(warnings, "scanner: "+e)
	}
	s.complete(ctx, r.id, store.NetScanResult{
		Status: models.NetScanCompleted, Reason: res.Reason, TemplatesVersion: res.templatesVersion(),
		OpenPorts: len(res.OpenPorts), Listeners: listeners, Warnings: warnings, DurationSec: res.DurationSec,
		Services: services, Findings: findings,
	}, label, r.t.Path)
}

func (s *Service) complete(ctx context.Context, id uuid.UUID, res store.NetScanResult, label, path string) {
	if err := s.store.CompleteNetScan(ctx, id, res); err != nil {
		s.log.Warn("netscan: store result", "target", label, "path", path, "err", err)
		if !errors.Is(err, store.ErrNetScanGone) {
			_ = s.store.FailNetScan(ctx, id, "store result: "+err.Error())
		}
		return
	}
	s.log.Info("netscan completed", "target", label, "path", path, "status", res.Status,
		"open", res.OpenPorts, "findings", len(res.Findings))
	if res.Status == models.NetScanCompleted {
		s.notifyExposure(ctx, id, label, path, res.Services, res.Findings)
	}
}

// notifyExposure announces ports that were not open on the previous scan of the same
// address and path, and any critical or high finding.
func (s *Service) notifyExposure(ctx context.Context, id uuid.UUID, label, path string,
	services []models.NetService, findings []models.NetFinding) {
	if s.nfy == nil {
		return
	}
	var newPorts []string
	if prev, ok, err := s.store.PreviousNetPorts(ctx, id); err == nil && ok {
		for _, sv := range services {
			k := fmt.Sprintf("%s/%d", sv.Proto, sv.Port)
			if !prev[k] {
				desc := k
				if sv.Service != "" {
					desc += " (" + sv.Service + ")"
				}
				newPorts = append(newPorts, desc)
			}
		}
	}
	var serious []string
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "high" {
			serious = append(serious, fmt.Sprintf("%s [%s] on %d/%s", f.Name, f.Severity, f.Port, f.Proto))
		}
	}
	if len(newPorts) == 0 && len(serious) == 0 {
		return
	}
	var body []string
	if len(newPorts) > 0 {
		body = append(body, fmt.Sprintf("Newly reachable since the last scan: %s.", strings.Join(capList(newPorts, 10), ", ")))
	}
	if len(serious) > 0 {
		body = append(body, fmt.Sprintf("Serious findings: %s.", strings.Join(capList(serious, 10), "; ")))
	}
	s.nfy.Notify(ctx, notify.Event{
		Type: notify.EventNetExposure, Severity: notify.SeverityWarning,
		Title:     fmt.Sprintf("Network scan: %s (%s)", label, path),
		Body:      strings.Join(body, " "),
		DedupeKey: label + "|" + path,
	})
}

func capList(v []string, n int) []string {
	if len(v) <= n {
		return v
	}
	return append(v[:n:n], fmt.Sprintf("and %d more", len(v)-n))
}

// collectListeners asks the host what it has bound. Best-effort: on failure it
// returns nil (unknown) and a warning that says what the scan therefore cannot do.
func (s *Service) collectListeners(ctx context.Context, h *models.Host) ([]models.NetListener, string) {
	const lost = " Unexpected-port detection and exposure context are off for this scan."
	if !h.Enrolled {
		return nil, "The host is not enrolled, so its own listener list could not be collected." + lost
	}
	if s.gw == nil || s.issuer == nil {
		return nil, "No SSH gateway is available to collect the host's listener list." + lost
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var ls []models.NetListener
	var err error
	if h.Protocol == "rdp" {
		ls, err = s.windowsListeners(cctx, h)
	} else {
		ls, err = s.linuxListeners(cctx, h)
	}
	if err != nil {
		s.log.Debug("netscan: listeners", "host", h.Hostname, "err", err)
		return nil, "The host's listener list could not be collected (" + truncate(err.Error(), 200) + ")." + lost
	}
	return ls, ""
}

func (s *Service) linuxListeners(ctx context.Context, h *models.Host) ([]models.NetListener, error) {
	signer, err := s.issuer.SystemSigner(ctx, s.issuer.SystemHostPrincipals(h.ID), 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("system signer: %w", err)
	}
	var conn *sshgw.Conn
	var lastErr error
	for _, addr := range dedupe([]string{h.WGAddress, h.Address, h.Hostname}) {
		if conn, lastErr = s.gw.DialWithSigner(ctx, signer, addr, h.SSHPort, h.SSHUser); lastErr == nil {
			break
		}
	}
	if conn == nil {
		return nil, fmt.Errorf("dial host: %w", lastErr)
	}
	defer conn.Close()
	out, err := runCapture(ctx, conn.Client, listenerScript(), 4<<20)
	if err != nil {
		return nil, err
	}
	return parseListeners(out), nil
}

func (s *Service) windowsListeners(ctx context.Context, h *models.Host) ([]models.NetListener, error) {
	signer, err := s.issuer.SystemSigner(ctx, s.issuer.SystemHostPrincipals(h.ID), 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("system signer: %w", err)
	}
	jump, err := s.gw.DialJumpWithSigner(ctx, signer)
	if err != nil {
		return nil, fmt.Errorf("dial jump host: %w", err)
	}
	defer jump.Close()
	key, err := s.cfg.VaultKey()
	if err != nil {
		return nil, fmt.Errorf("vault key: %w", err)
	}
	user, pass, err := credinject.PasswordForSystem(ctx, s.store, key, s.cfg.ExtSecret(), h)
	if err != nil {
		return nil, fmt.Errorf("credential: %w", err)
	}
	cands := winrm.ManagementAddrs(h.WGAddress, h.Address, h.Hostname, h.Enrolled)
	if len(cands) == 0 {
		return nil, fmt.Errorf("host has no address")
	}
	dial := func(_, addr string) (net.Conn, error) { return jump.DialContext(ctx, "tcp", addr) }
	stdout, stderr, code, err := winrm.RunScript(ctx, dial, cands[0], user, pass, s.cfg.RDPWinRMPorts,
		windowsListenerScript, 2*time.Minute)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("listener script exited %d: %s", code, truncate(stderr, 200))
	}
	return parseWindowsListeners(stdout), nil
}

// runCapture runs a script and returns bounded stdout, killing the session if ctx
// ends first.
func runCapture(ctx context.Context, c *ssh.Client, script string, limit int) (string, error) {
	sess, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	buf := &capBuffer{limit: limit}
	sess.Stdout = buf
	done := make(chan error, 1)
	go func() { done <- sess.Run(script) }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return "", ctx.Err()
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("listener collection failed: %w", err)
		}
		return string(buf.b), nil
	}
}

type capBuffer struct {
	limit int
	b     []byte
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if room := c.limit - len(c.b); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		c.b = append(c.b, p...)
	}
	return len(p), nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// --- ranges --------------------------------------------------------------------------

// rangeConcurrency bounds addresses of one range scanned at once.
const rangeConcurrency = 2

// StartRange discovers live addresses in a range and scans each, in the background.
// It returns the run id at once; rows appear as addresses are found. wait blocks
// until the run has finished, and returns the discovery error if there was one.
func (s *Service) StartRange(bg context.Context, rng *models.NetScanRange, by *uuid.UUID,
	requester string, scheduled bool) (uuid.UUID, func() error, error) {
	if !s.Configured() {
		return uuid.Nil, func() error { return nil }, ErrNotConfigured
	}
	runID := uuid.New()
	done := make(chan error, 1)
	go func() { done <- s.runRange(bg, runID, rng, by, requester, scheduled) }()
	var once sync.Once
	var result error
	return runID, func() error {
		once.Do(func() { result = <-done })
		return result
	}, nil
}

func (s *Service) runRange(ctx context.Context, runID uuid.UUID, rng *models.NetScanRange, by *uuid.UUID,
	requester string, scheduled bool) error {
	dctx, cancel := context.WithTimeout(ctx, s.cfg.NetScanTimeout+time.Minute)
	addrs, err := s.sc.discover(dctx, rng.CIDR)
	cancel()
	if err != nil {
		s.log.Warn("netscan range discovery failed", "range", rng.Name, "cidr", rng.CIDR, "err", err)
		return fmt.Errorf("discover %s: %w", rng.CIDR, err)
	}
	jump := s.jumpAddrs(ctx)
	hostIDs, err := s.store.HostIDsByAddress(ctx)
	if err != nil {
		hostIDs = map[string]uuid.UUID{}
	}
	sem := make(chan struct{}, rangeConcurrency)
	var wg sync.WaitGroup
	for _, a := range addrs {
		if jump[a] && !s.cfg.NetScanIncludeJumpHost {
			continue
		}
		var hid *uuid.UUID
		if id, ok := hostIDs[a]; ok {
			hid = &id
		}
		rid := rng.ID
		id, err := s.store.CreateNetScan(ctx, runID, hid, &rid, a, models.NetPathRange, by, requester, scheduled)
		if err != nil {
			s.log.Warn("netscan range: create scan", "addr", a, "err", err)
			continue
		}
		if err := s.store.StartNetScan(ctx, id); err != nil {
			s.log.Warn("netscan range: start", "addr", a, "err", err)
		}
		wg.Add(1)
		go func(id uuid.UUID, a string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			s.scanOne(ctx, row{id: id, t: target{Path: models.NetPathRange, Addr: a}}, nil, nil, "",
				[]int{22, 80, 443, 3389})
		}(id, a)
	}
	wg.Wait()
	s.log.Info("netscan range finished", "range", rng.Name, "cidr", rng.CIDR, "live", len(addrs))
	return nil
}

// --- status and templates ----------------------------------------------------------

// Status is what the UI shows about the scanner.
type Status struct {
	Configured     bool             `json:"configured"`
	Health         *Health          `json:"health,omitempty"`
	HealthError    string           `json:"healthError,omitempty"`
	Templates      *TemplatesStatus `json:"templates,omitempty"`
	TemplatesError string           `json:"templatesError,omitempty"`
	// TemplatesStale: the templates are older than one missed daily refresh.
	TemplatesStale bool `json:"templatesStale"`
}

// staleTemplatesAfter matches vulnscan's stale-database threshold: daily refresh,
// one miss allowed.
const staleTemplatesAfter = 36 * time.Hour

// Status reports configuration, sidecar health and template freshness.
func (s *Service) Status(ctx context.Context) Status {
	st := Status{Configured: s.Configured()}
	if !st.Configured {
		st.HealthError = ErrNotConfigured.Error()
		return st
	}
	if h, err := s.sc.health(ctx); err != nil {
		st.HealthError = err.Error()
	} else {
		st.Health = h
	}
	if t, err := s.sc.templatesStatus(ctx); err != nil {
		st.TemplatesError = err.Error()
	} else {
		st.Templates = t
		if ts, err := time.Parse(time.RFC3339, t.UpdatedAt); err == nil && time.Since(ts) > staleTemplatesAfter {
			st.TemplatesStale = true
		}
	}
	return st
}

// TemplatesUpdate refreshes the nuclei templates online.
func (s *Service) TemplatesUpdate(ctx context.Context) (*TemplatesStatus, error) {
	return s.sc.templatesPost(ctx, "/templates/update", nil, "application/json", "")
}

// TemplatesImport installs an offline templates archive.
func (s *Service) TemplatesImport(ctx context.Context, archive io.Reader, version string) (*TemplatesStatus, error) {
	return s.sc.templatesPost(ctx, "/templates/import", archive, "application/gzip", version)
}
