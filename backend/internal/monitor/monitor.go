// Package monitor performs authenticated SSH health checks (no ICMP) against
// enrolled hosts through the jump host, updates host_status, and pushes live
// updates to dashboards over the WebSocket hub.
package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/credinject"
	"github.com/fleet-terminal/backend/internal/identity"
	"github.com/fleet-terminal/backend/internal/jobs"
	"github.com/fleet-terminal/backend/internal/metrics"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/sshgw"
	"github.com/fleet-terminal/backend/internal/store"
	"github.com/fleet-terminal/backend/internal/winrm"
	"github.com/fleet-terminal/backend/internal/ws"
)

// Monitor periodically probes hosts and reports their health.
type Monitor struct {
	store  *store.Store
	cfg    *config.Config
	log    *slog.Logger
	gw     *sshgw.Gateway
	issuer *identity.Issuer
	hub    *ws.Hub
	jobs   *jobs.Registry
	nfy    *notify.Service

	interval time.Duration
}

// New constructs a Monitor.
func New(st *store.Store, cfg *config.Config, log *slog.Logger, gw *sshgw.Gateway, issuer *identity.Issuer, hub *ws.Hub, reg *jobs.Registry, nfy *notify.Service) *Monitor {
	return &Monitor{store: st, cfg: cfg, log: log, gw: gw, issuer: issuer, hub: hub, jobs: reg, nfy: nfy, interval: 30 * time.Second}
}

// notifyTransition emits an alert when a host crosses the online/offline
// boundary. The first observation (no prior status) is skipped to avoid a burst
// of spurious alerts on startup.
func (m *Monitor) notifyTransition(ctx context.Context, h models.Host, prev, now string) {
	if m.nfy == nil || prev == "" || prev == now {
		return
	}
	switch {
	case prev == "online" && now == "offline":
		m.nfy.Notify(ctx, notify.Event{
			Type: notify.EventHostOffline, Severity: notify.SeverityError,
			Title:     "Host offline: " + h.Hostname,
			Body:      fmt.Sprintf("Fleet can no longer reach %s (%s). It was last seen online.", h.Hostname, h.Environment),
			DedupeKey: h.ID.String(),
		})
	case prev != "online" && now == "online":
		m.nfy.Notify(ctx, notify.Event{
			Type: notify.EventHostRecovered, Severity: notify.SeverityInfo,
			Title:     "Host recovered: " + h.Hostname,
			Body:      fmt.Sprintf("%s (%s) is reachable again.", h.Hostname, h.Environment),
			DedupeKey: h.ID.String(),
		})
	}
}

// Run drives the monitoring loop until ctx is cancelled.
// Run drives the host-monitor sweep loop. leader gates the sweep so that in a
// multi-instance (HA) deployment only the leader probes hosts and writes status
// (avoiding N× SSH probes and status races); pass nil for a single-instance
// deployment. Status changes still reach every instance's clients via the event
// backplane.
func (m *Monitor) Run(ctx context.Context, leader func() bool) {
	// Initial probe shortly after startup, then on the interval.
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			t.Reset(m.interval)
			if leader != nil && !leader() {
				continue
			}
			m.sweep(ctx)
		}
	}
}

// monitorConcurrency returns how many hosts to probe at once. Each probe opens a
// fresh SSH connection to the jump host, so this stays well under the jump host's
// sshd MaxStartups pre-auth limit (OpenSSH default 10), leaving headroom for user
// terminals and KRL pushes: too high and a rotating subset of probes is refused,
// flapping hosts offline; a small pool still keeps a few unreachable hosts from
// stalling the whole sweep.
func (m *Monitor) monitorConcurrency() int {
	if n := m.cfg.MonitorConcurrency; n >= 1 {
		return n
	}
	return 6
}

// sweep probes every enrolled host once, in parallel with a bounded worker pool.
func (m *Monitor) sweep(ctx context.Context) {
	hosts, err := m.store.AllHosts(ctx)
	if err != nil {
		m.log.Warn("monitor list hosts", "err", err)
		if m.jobs != nil {
			m.jobs.Record("host-monitor", err)
		}
		return
	}
	sem := make(chan struct{}, m.monitorConcurrency())
	var wg sync.WaitGroup
	for i := range hosts {
		h := hosts[i]
		// SSH hosts are probed once enrolled; RDP hosts are never "enrolled" (Windows
		// can't run the enrollment script) but are still reachable through the jump
		// host, so probe them via a TCP check on the RDP port.
		if !h.Enrolled && h.Protocol != "rdp" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			m.probeHost(ctx, h)
		}()
	}
	wg.Wait()
	m.refreshGauges(ctx)
	if m.jobs != nil {
		m.jobs.Record("host-monitor", nil)
	}
}

// probeHost checks one host and persists its status/inventory/metrics. Safe to
// run concurrently across hosts: every write targets that host's own rows and
// pgxpool, the hub, and the notifier are all concurrency-safe.
func (m *Monitor) probeHost(ctx context.Context, h models.Host) {
	signer, err := m.issuer.SystemSigner(ctx, m.issuer.SystemHostPrincipals(h.ID), 24*time.Hour)
	if err != nil {
		m.log.Warn("monitor system signer", "host", h.Hostname, "err", err)
		return
	}
	prev := ""
	if h.Status != nil {
		prev = h.Status.Status
	}

	// RDP hosts have no SSH: probe TCP reachability of the RDP port, and (best-effort)
	// collect Windows facts over WinRM instead of the SSH inventory path.
	if h.Protocol == "rdp" {
		st := m.probeRDP(ctx, signer, &h)
		var inv *models.HostInventory
		if m.cfg.RDPCollectFacts && st.Status == "online" && inventoryStale(h.Inventory) {
			if f := m.collectWindowsFacts(ctx, signer, &h); f != nil {
				inv = f.inv
				if f.uptime > 0 {
					up := f.uptime
					st.UptimeSeconds = &up
				}
			}
		}
		if err := m.store.UpdateStatus(ctx, h.ID, st); err != nil {
			m.log.Warn("monitor update status", "host", h.Hostname, "err", err)
			return
		}
		m.notifyTransition(ctx, h, prev, st.Status)
		if inv != nil {
			if err := m.store.UpsertInventory(ctx, h.ID, *inv); err != nil {
				m.log.Warn("monitor update inventory", "host", h.Hostname, "err", err)
			}
		}
		m.broadcastStatus(h, st)
		return
	}

	st, inv, metrics := m.probe(ctx, signer, &h)
	if err := m.store.UpdateStatus(ctx, h.ID, st); err != nil {
		m.log.Warn("monitor update status", "host", h.Hostname, "err", err)
		return
	}
	m.notifyTransition(ctx, h, prev, st.Status)
	if inv != nil {
		if err := m.store.UpsertInventory(ctx, h.ID, *inv); err != nil {
			m.log.Warn("monitor update inventory", "host", h.Hostname, "err", err)
		}
	}
	if metrics != nil {
		if err := m.store.UpsertMetrics(ctx, h.ID, *metrics); err != nil {
			m.log.Warn("monitor update metrics", "host", h.Hostname, "err", err)
		}
		// Append to the metric history time series (throttled to the configured
		// sample cadence in the store). Skipped when history is disabled.
		if m.cfg.MetricHistoryRetention > 0 {
			if err := m.store.RecordMetricHistory(ctx, h.ID, *metrics, m.cfg.MetricHistorySample); err != nil {
				m.log.Warn("monitor record metric history", "host", h.Hostname, "err", err)
			}
		}
	}
	m.broadcastStatus(h, st)
}

// broadcastStatus pushes a host's freshly-probed status to connected dashboards.
func (m *Monitor) broadcastStatus(h models.Host, st models.HostStatus) {
	m.hub.Broadcast("host.status", map[string]any{
		"hostId": h.ID, "hostname": h.Hostname, "status": st.Status,
		"latencyMs": st.LatencyMS, "sshOk": st.SSHOK, "wgOk": st.WGOK,
		"uptimeSeconds": st.UptimeSeconds, "checkedAt": time.Now(),
	})
}

// probeRDP health-checks an RDP host by testing TCP reachability to its RDP port
// through the jump host. Windows hosts expose no SSH, so the standard authenticated
// probe (and its inventory/metrics) does not apply — this only reports online/offline
// plus connect latency.
func (m *Monitor) probeRDP(ctx context.Context, signer ssh.Signer, h *models.Host) models.HostStatus {
	now := time.Now()
	st := models.HostStatus{Status: "unknown", CheckedAt: &now}
	port := h.RDPPort
	if port <= 0 {
		port = 3389
	}
	var dialErr error
	for _, addr := range dedupe([]string{h.WGAddress, h.Address, h.Hostname}) {
		start := time.Now()
		if dialErr = m.gw.ProbeTCPViaJump(ctx, signer, addr, port); dialErr == nil {
			lat := int(time.Since(start).Milliseconds())
			st.LatencyMS = &lat
			st.Status = "online"
			st.LastSuccessAt = &now
			return st
		}
	}
	st.Status = "offline"
	st.LastError = trunc(errStr(dialErr), 240)
	st.LastFailureAt = &now
	return st
}

type winFacts struct {
	inv    *models.HostInventory
	uptime int64
}

// collectWindowsFacts gathers OS/CPU/memory/uptime from a Windows RDP host over WinRM,
// authenticated with the host's open-policy vault credential and tunneled through the
// jump host. Best-effort: any failure (no credential, WinRM unreachable, auth) returns
// nil and is logged at debug — the host's status is unaffected.
func (m *Monitor) collectWindowsFacts(ctx context.Context, signer ssh.Signer, h *models.Host) *winFacts {
	key, err := m.cfg.VaultKey()
	if err != nil {
		return nil
	}
	user, pass, err := credinject.PasswordForSystem(ctx, m.store, key, h)
	if err != nil {
		m.log.Debug("rdp facts: no usable credential", "host", h.Hostname, "err", err)
		return nil
	}
	cands := dedupe([]string{h.WGAddress, h.Address, h.Hostname})
	if len(cands) == 0 {
		return nil
	}
	jump, err := m.gw.DialJumpWithSigner(ctx, signer)
	if err != nil {
		m.log.Debug("rdp facts: dial jump host", "host", h.Hostname, "err", err)
		return nil
	}
	defer jump.Close()
	dial := func(_ /*network*/, addr string) (net.Conn, error) { return jump.DialContext(ctx, "tcp", addr) }
	f, err := winrm.Collect(ctx, dial, cands[0], user, pass, m.cfg.RDPWinRMPorts)
	if err != nil {
		m.log.Debug("rdp facts: winrm collect", "host", h.Hostname, "err", err)
		return nil
	}
	now := time.Now()
	return &winFacts{
		inv: &models.HostInventory{
			OSName: f.OS, OSVersion: f.OSVersion, Architecture: f.Architecture,
			CPUCount: f.CPUCount, MemoryMB: f.MemoryMB, CollectedAt: &now,
		},
		uptime: f.UptimeSeconds,
	}
}

// probe runs a lightweight authenticated SSH command through the jump host and
// records latency, uptime, and SSH/WireGuard health. When the host is online and
// its inventory is missing or stale, it also re-collects host facts (distro,
// kernel, etc.) over the same connection and returns them for persistence.
func (m *Monitor) probe(ctx context.Context, signer ssh.Signer, h *models.Host) (models.HostStatus, *models.HostInventory, *models.HostMetrics) {
	now := time.Now()
	st := models.HostStatus{Status: "unknown", CheckedAt: &now}

	candidates := dedupe([]string{h.WGAddress, h.Address, h.Hostname})
	var conn *sshgw.Conn
	var dialErr error
	for _, addr := range candidates {
		start := time.Now()
		conn, dialErr = m.gw.DialWithSigner(ctx, signer, addr, h.SSHPort, h.SSHUser)
		if dialErr == nil {
			lat := int(time.Since(start).Milliseconds())
			st.LatencyMS = &lat
			// If we reached it via the WireGuard address, the overlay is healthy.
			st.WGOK = addr == h.WGAddress && h.WGAddress != ""
			break
		}
	}
	if dialErr != nil || conn == nil {
		st.Status = "offline"
		st.SSHOK = false
		st.LastError = trunc(errStr(dialErr), 240)
		st.LastFailureAt = &now
		return st, nil, nil
	}
	defer conn.Close()
	st.SSHOK = true
	st.Status = "online"
	st.LastSuccessAt = &now

	if out, err := runCmd(conn, "cat /proc/uptime 2>/dev/null"); err == nil {
		st.UptimeSeconds = parseUptime(out)
	}
	// WireGuard handshake freshness (best-effort; requires sudo on the host).
	if !st.WGOK {
		if out, err := runCmd(conn, "sudo wg show "+m.cfg.WGInterface+" latest-handshakes 2>/dev/null | awk '{print $2}' | sort -rn | head -1"); err == nil {
			if hs := strings.TrimSpace(out); hs != "" && hs != "0" {
				if v, perr := strconv.ParseInt(hs, 10, 64); perr == nil && time.Now().Unix()-v < 180 {
					st.WGOK = true
				}
			}
		}
	}

	// Refresh host facts at most once per inventoryTTL — they change rarely
	// (reboots, package upgrades), so there's no need to re-collect every probe.
	var inv *models.HostInventory
	if inventoryStale(h.Inventory) {
		if collected, ok := collectInventory(conn); ok {
			inv = &collected
		}
	}

	// Resource metrics (disk/memory/load/network) change continuously, so collect
	// them every probe. CPU count (for load-per-core) comes from inventory.
	cpu := 0
	if h.Inventory != nil {
		cpu = h.Inventory.CPUCount
	}
	if inv != nil && inv.CPUCount > 0 {
		cpu = inv.CPUCount
	}
	metrics := collectMetrics(conn, cpu)

	return st, inv, metrics
}

// inventoryTTL bounds how often the monitor re-collects host facts.
const inventoryTTL = time.Hour

func inventoryStale(inv *models.HostInventory) bool {
	return inv == nil || inv.CollectedAt == nil || time.Since(*inv.CollectedAt) > inventoryTTL
}

// collectInventory gathers host facts over an open connection: kernel, arch,
// distro + version, SSH version, CPU count, and total memory. Best-effort — a
// missing field is left zero rather than failing the whole probe.
func collectInventory(conn *sshgw.Conn) (models.HostInventory, bool) {
	const cmd = `uname -s; uname -r; uname -m; ` +
		`(. /etc/os-release 2>/dev/null; echo "$NAME $VERSION_ID"); ` +
		`ssh -V 2>&1 | head -1; nproc 2>/dev/null; ` +
		`awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null`
	out, err := runCmd(conn, cmd)
	if err != nil {
		return models.HostInventory{}, false
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	field := func(i int) string {
		if i < len(lines) {
			return strings.TrimSpace(lines[i])
		}
		return ""
	}
	now := time.Now()
	inv := models.HostInventory{
		OSName:        field(0), // uname -s; overridden by /etc/os-release below when present
		KernelVersion: field(1),
		Architecture:  field(2),
		SSHVersion:    field(4),
		CollectedAt:   &now,
	}
	if os := field(3); os != "" {
		inv.OSName = os
	}
	if n, perr := strconv.Atoi(field(5)); perr == nil {
		inv.CPUCount = n
	}
	if kb, perr := strconv.ParseInt(field(6), 10, 64); perr == nil {
		inv.MemoryMB = kb / 1024
	}
	collectUpdates(conn, &inv)
	return inv, true
}

// collectUpdates counts pending package updates from the host's *cached* package
// metadata (no network refresh, so it's cheap and reflects the host's own update
// cadence). Output is "total;security"; best-effort across apt/dnf/yum. A failure
// leaves the fields nil so the last-known counts are preserved.
func collectUpdates(conn *sshgw.Conn, inv *models.HostInventory) {
	const cmd = `
if command -v apt-get >/dev/null 2>&1; then
  if [ -x /usr/lib/update-notifier/apt-check ]; then
    /usr/lib/update-notifier/apt-check 2>&1
  else
    up=$(apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null | grep -c '^Inst')
    sec=$(apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null | grep '^Inst' | grep -ci 'security')
    echo "$up;$sec"
  fi
elif command -v dnf >/dev/null 2>&1; then
  up=$(dnf -q -C check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9._+-]+[[:space:]]')
  sec=$(dnf -q -C updateinfo list security 2>/dev/null | grep -cE '^[A-Za-z]')
  echo "$up;$sec"
elif command -v yum >/dev/null 2>&1; then
  up=$(yum -q -C check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9._+-]+[[:space:]]')
  echo "$up;0"
fi`
	out, err := runCmd(conn, cmd)
	if err != nil {
		return
	}
	line := strings.TrimSpace(out)
	total, sec, ok := strings.Cut(line, ";")
	if !ok {
		return
	}
	t, terr := strconv.Atoi(strings.TrimSpace(total))
	if terr != nil {
		return
	}
	now := time.Now()
	inv.UpdatesAvailable = &t
	inv.UpdatesCheckedAt = &now
	if s, serr := strconv.Atoi(strings.TrimSpace(sec)); serr == nil {
		inv.SecurityUpdates = &s
	}
}

func runCmd(conn *sshgw.Conn, cmd string) (string, error) {
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
	var out []string
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (m *Monitor) refreshGauges(ctx context.Context) {
	counts, err := m.store.CountHostsByStatus(ctx)
	if err != nil {
		return
	}
	for status, n := range counts {
		metrics.HostsByStatus.WithLabelValues(status).Set(float64(n))
	}
}

// parseUptime extracts seconds from the contents of /proc/uptime.
func parseUptime(s string) *int64 {
	fields := strings.Fields(strings.TrimSpace(s))
	if len(fields) == 0 {
		return nil
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return nil
	}
	v := int64(f)
	return &v
}
