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

// recordTransition persists an availability transition to the history table and
// then emits the alert. Persisting is factual and happens even inside a
// maintenance window (which only suppresses the alert), so downtime is always
// answerable after the fact. The first observation (prev == "") is skipped, and
// only definite online<->offline flips are recorded — "unknown" (a probe that
// could not run, e.g. a signer error) is not a reachability change.
func (m *Monitor) recordTransition(ctx context.Context, h models.Host, prev, now, lastErr string) {
	if prev != "" && prev != now &&
		(prev == "online" || prev == "offline") && (now == "online" || now == "offline") {
		if err := m.store.RecordStatusEvent(ctx, h.ID, prev, now, lastErr, time.Now()); err != nil {
			m.log.Warn("monitor record status event", "host", h.Hostname, "err", err)
		}
	}
	m.notifyTransition(ctx, h, prev, now)
}

// notifyTransition emits an alert when a host crosses the online/offline
// boundary. The first observation (no prior status) is skipped to avoid a burst
// of spurious alerts on startup.
func (m *Monitor) notifyTransition(ctx context.Context, h models.Host, prev, now string) {
	if m.nfy == nil || prev == "" || prev == now {
		return
	}
	// Suppress offline/recovered alerts while the host is in a maintenance window
	// (e.g. an operator patching or rebooting it).
	if h.InMaintenance() {
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
			if leader != nil && !leader() {
				// Not leader yet (e.g. still acquiring leadership after a restart):
				// poll frequently so the first sweep happens within seconds of taking
				// over, instead of waiting up to a full interval (which would keep
				// hosts showing offline long after leadership is settled).
				t.Reset(5 * time.Second)
				continue
			}
			m.sweep(ctx)
			t.Reset(m.interval)
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
	// collect Windows facts over WinRM instead of the SSH inventory path. Both use a
	// single jump-host connection per probe — same jump-connection cost as an SSH host,
	// so RDP hosts scale under the shared worker pool identically.
	if h.Protocol == "rdp" {
		var st models.HostStatus
		var inv *models.HostInventory
		var metrics *models.HostMetrics
		jump, jerr := m.gw.DialJumpWithSigner(ctx, signer)
		if jerr != nil {
			now := time.Now()
			st = models.HostStatus{Status: "offline", CheckedAt: &now, LastError: trunc(errStr(jerr), 240), LastFailureAt: &now}
		} else {
			st = m.probeRDPOver(ctx, jump, &h)
			// Collect over WinRM every sweep while online: inventory changes rarely but
			// resource metrics (disk, memory, network) are live, and it's a single call
			// reusing the jump connection we already opened.
			if m.cfg.RDPCollectFacts && st.Status == "online" {
				if f := m.collectWindowsFactsOver(ctx, jump, &h); f != nil {
					inv = f.inv
					metrics = f.metrics
					if f.uptime > 0 {
						up := f.uptime
						st.UptimeSeconds = &up
					}
				}
			}
			jump.Close()
		}
		if err := m.store.UpdateStatus(ctx, h.ID, st); err != nil {
			m.log.Warn("monitor update status", "host", h.Hostname, "err", err)
			return
		}
		m.recordTransition(ctx, h, prev, st.Status, st.LastError)
		if inv != nil {
			if err := m.store.UpsertInventory(ctx, h.ID, *inv); err != nil {
				m.log.Warn("monitor update inventory", "host", h.Hostname, "err", err)
			}
		}
		if metrics != nil {
			if err := m.store.UpsertMetrics(ctx, h.ID, *metrics); err != nil {
				m.log.Warn("monitor update metrics", "host", h.Hostname, "err", err)
			}
			if m.cfg.MetricHistoryRetention > 0 {
				if err := m.store.RecordMetricHistory(ctx, h.ID, *metrics, m.cfg.MetricHistorySample); err != nil {
					m.log.Warn("monitor record metric history", "host", h.Hostname, "err", err)
				}
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
	m.recordTransition(ctx, h, prev, st.Status, st.LastError)
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

// probeRDPOver health-checks an RDP host by testing TCP reachability to its RDP port
// over an already-open jump-host connection. Windows hosts expose no SSH, so the
// standard authenticated probe (and its inventory/metrics) does not apply — this only
// reports online/offline plus connect latency.
func (m *Monitor) probeRDPOver(ctx context.Context, jump *ssh.Client, h *models.Host) models.HostStatus {
	now := time.Now()
	st := models.HostStatus{Status: "unknown", CheckedAt: &now}
	port := h.RDPPort
	if port <= 0 {
		port = 3389
	}
	var dialErr error
	for _, addr := range dedupe([]string{h.WGAddress, h.Address, h.Hostname}) {
		start := time.Now()
		conn, err := jump.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
		if err == nil {
			_ = conn.Close()
			lat := int(time.Since(start).Milliseconds())
			st.LatencyMS = &lat
			st.Status = "online"
			st.LastSuccessAt = &now
			// If we reached the RDP port over the WireGuard address, the overlay is up.
			st.WGOK = addr == h.WGAddress && h.WGAddress != ""
			return st
		}
		dialErr = err
	}
	st.Status = "offline"
	st.LastError = trunc(errStr(dialErr), 240)
	st.LastFailureAt = &now
	return st
}

type winFacts struct {
	inv     *models.HostInventory
	metrics *models.HostMetrics
	uptime  int64
}

// collectWindowsFactsOver gathers OS/CPU/memory/disk/network facts from a Windows RDP
// host over WinRM, authenticated with the host's open-policy vault credential and
// tunneled through the supplied (already-open) jump-host connection. Best-effort: any
// failure (no credential, WinRM unreachable, auth) returns nil and is logged at debug —
// the host's status is unaffected.
func (m *Monitor) collectWindowsFactsOver(ctx context.Context, jump *ssh.Client, h *models.Host) *winFacts {
	key, err := m.cfg.VaultKey()
	if err != nil {
		return nil
	}
	user, pass, err := credinject.PasswordForSystem(ctx, m.store, key, m.cfg.ExtSecret(), h)
	if err != nil {
		m.log.Debug("rdp facts: no usable credential", "host", h.Hostname, "err", err)
		return nil
	}
	cands := dedupe([]string{h.WGAddress, h.Address, h.Hostname})
	if len(cands) == 0 {
		return nil
	}
	dial := func(_ /*network*/, addr string) (net.Conn, error) { return jump.DialContext(ctx, "tcp", addr) }
	// The pending-updates search (Windows Update Agent) is heavier than the WMI
	// facts, so run it only when the last check is stale (hourly) rather than every
	// sweep — the counts are preserved by UpsertInventory's COALESCE in between.
	dueUpdates := updatesStale(h.Inventory)
	f, err := winrm.Collect(ctx, dial, cands[0], user, pass, m.cfg.RDPWinRMPorts, dueUpdates)
	if err != nil {
		m.log.Debug("rdp facts: winrm collect", "host", h.Hostname, "err", err)
		return nil
	}
	// Refresh the installed-software inventory on the same (hourly) cadence as the
	// updates search, so the software-inventory view stays current without scanning.
	if dueUpdates {
		if sw, serr := winrm.CollectSoftware(ctx, dial, cands[0], user, pass, m.cfg.RDPWinRMPorts, 3*time.Minute); serr == nil {
			items := make([]models.WindowsSoftware, 0, len(sw))
			for _, s := range sw {
				items = append(items, models.WindowsSoftware{Name: s.Name, Version: s.Version, Publisher: s.Publisher})
			}
			if perr := m.store.ReplaceWindowsSoftware(ctx, h.ID, items); perr != nil {
				m.log.Warn("rdp software inventory persist", "host", h.Hostname, "err", perr)
			}
		} else {
			m.log.Debug("rdp software inventory", "host", h.Hostname, "err", serr)
		}
	}
	now := time.Now()
	inv := &models.HostInventory{
		OSName: f.OS, OSVersion: f.OSVersion, Architecture: f.Architecture,
		CPUCount: f.CPUCount, MemoryMB: f.MemoryMB, CollectedAt: &now,
	}
	// Pending Windows Update counts (nil unless the search ran this call) — same
	// inventory fields the Linux apt/dnf path fills, so the assistant and dashboard
	// surface Windows update posture with no further changes.
	if f.UpdatesAvailable != nil {
		inv.UpdatesAvailable = f.UpdatesAvailable
		inv.SecurityUpdates = f.SecurityUpdates
		inv.UpdatesCheckedAt = &now
	}

	// Resource metrics — same HostMetrics shape as the Linux path so the UI renders
	// them identically. Load average is a Unix concept and is left nil for Windows.
	var disks []models.DiskFS
	var minFreePct *float64
	for _, d := range f.Disks {
		used := d.SizeBytes - d.FreeBytes
		usePct := float64(used) / float64(d.SizeBytes) * 100
		disks = append(disks, models.DiskFS{
			Mount: d.Mount, SizeBytes: d.SizeBytes, UsedBytes: used,
			AvailBytes: d.FreeBytes, UsePct: usePct,
		})
		if freePct := 100 - usePct; minFreePct == nil || freePct < *minFreePct {
			fp := freePct
			minFreePct = &fp
		}
	}
	var net *models.HostNetwork
	if len(f.Interfaces) > 0 || f.Gateway != "" {
		net = &models.HostNetwork{DefaultGateway: f.Gateway}
		for _, ni := range f.Interfaces {
			net.Interfaces = append(net.Interfaces, models.NetInterface{Name: ni.Name, Addrs: ni.Addrs})
		}
	}
	primaryIP := windowsPrimaryIP(f.Interfaces, h.WGAddress)
	metrics := &models.HostMetrics{
		Disk: disks, MinDiskFreePct: minFreePct,
		MemTotalMB: f.MemoryMB, MemAvailableMB: f.MemFreeMB,
		Network: net, PrimaryIP: primaryIP, CollectedAt: &now,
	}
	if f.MemoryMB > 0 {
		usedPct := float64(f.MemoryMB-f.MemFreeMB) / float64(f.MemoryMB) * 100
		metrics.MemUsedPct = &usedPct
	}
	if net != nil {
		net.PrimaryIP = primaryIP
	}

	return &winFacts{inv: inv, metrics: metrics, uptime: f.UptimeSeconds}
}

// windowsPrimaryIP picks the host's main IPv4 from its interfaces: the first address
// that isn't loopback, link-local, or the WireGuard overlay address.
func windowsPrimaryIP(ifaces []winrm.Iface, wgAddr string) string {
	for _, ni := range ifaces {
		for _, a := range ni.Addrs {
			if !strings.Contains(a, ".") { // skip IPv6
				continue
			}
			if a == wgAddr || strings.HasPrefix(a, "127.") || strings.HasPrefix(a, "169.254.") {
				continue
			}
			return a
		}
	}
	return ""
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

// updatesStale bounds how often the pending-updates search runs (heavier than the
// rest of fact collection), independent of the live per-sweep metrics.
func updatesStale(inv *models.HostInventory) bool {
	return inv == nil || inv.UpdatesCheckedAt == nil || time.Since(*inv.UpdatesCheckedAt) > inventoryTTL
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

// updatePackagesCap bounds how many pending-update package rows we store per host, so
// a badly-out-of-date host can't bloat the inventory row (the counts are still exact).
const updatePackagesCap = 500

// collectUpdates gathers pending package updates from the host's *cached* package
// metadata (no network refresh, so it's cheap and reflects the host's own update
// cadence). It emits a `COUNTS|total|security` line plus one `PKG|name|version|sec`
// line per upgradable package (best-effort across apt/dnf/yum). A failure leaves the
// fields nil so the last-known values are preserved.
func collectUpdates(conn *sshgw.Conn, inv *models.HostInventory) {
	const cmd = `
if command -v apt-get >/dev/null 2>&1; then
  # 'apt list --upgradable' enumerates EVERY upgradable package from the cached
  # metadata — matching what 'apt update' reports as "N can be upgraded", including
  # packages that 'apt-get upgrade' holds back (ones needing new dependencies and
  # Ubuntu phased updates). The old 'apt-get -s upgrade' simulation silently
  # undercounted those to zero, so hosts with only kept-back/phased updates showed
  # nothing pending here even though 'apt update' listed them.
  list=$(apt list --upgradable 2>/dev/null | grep '/')
  up=$(printf '%s\n' "$list" | grep -c '/')
  sec=$(printf '%s\n' "$list" | grep -Eci '/[^ ]*security')
  printf 'COUNTS|%s|%s\n' "$up" "$sec"
  printf '%s\n' "$list" | while IFS= read -r line; do
    [ -n "$line" ] || continue
    name=${line%%/*}
    ver=$(printf '%s' "$line" | awk '{print $2}')
    s=0; printf '%s' "$line" | grep -Eqi '/[^ ]*security' && s=1
    printf 'PKG|%s|%s|%s\n' "$name" "$ver" "$s"
  done
elif command -v dnf >/dev/null 2>&1; then
  # dnf repoquery gives clean machine-readable rows (no header/wrapping); --latest-limit 1
  # yields one row per package (matching 'dnf check-update'), and --security narrows to
  # security-relevant updates so EACH package is correctly flagged (the previous code
  # hard-coded every dnf package to non-security). dnf doesn't hold updates back the way
  # 'apt-get upgrade' does. Cache-only (-C) stays cheap; dnf-makecache.timer keeps it fresh.
  all=$(dnf -q -C repoquery --upgrades --latest-limit 1 --qf '%{name}.%{arch}|%{evr}\n' 2>/dev/null | sort -u)
  secset=$(dnf -q -C repoquery --upgrades --latest-limit 1 --security --qf '%{name}.%{arch}\n' 2>/dev/null | sort -u)
  if [ -z "$all" ]; then
    # Minimal install without repoquery: fall back to parsing check-update columns.
    all=$(dnf -q -C check-update 2>/dev/null | awk '$1 ~ /\.[a-z0-9_]+$/ && NF>=3 {print $1"|"$2}')
    secset=$(dnf -q -C --security check-update 2>/dev/null | awk '$1 ~ /\.[a-z0-9_]+$/ && NF>=3 {print $1}')
  fi
  up=$(printf '%s\n' "$all" | grep -c '|')
  sec=$(printf '%s\n' "$secset" | grep -c .)
  printf 'COUNTS|%s|%s\n' "$up" "$sec"
  printf '%s\n' "$all" | while IFS='|' read -r name ver; do
    [ -n "$name" ] || continue
    s=0; printf '%s\n' "$secset" | grep -qxF "$name" && s=1
    printf 'PKG|%s|%s|%s\n' "$name" "$ver" "$s"
  done
elif command -v yum >/dev/null 2>&1; then
  # RHEL 7 / older: yum has no built-in repoquery, so parse check-update columns
  # (name.arch version repo); flag security via yum-plugin-security when installed.
  all=$(yum -q -C check-update 2>/dev/null | awk '$1 ~ /\.[a-z0-9_]+$/ && NF>=3 {print $1"|"$2}')
  secset=$(yum -q -C --security check-update 2>/dev/null | awk '$1 ~ /\.[a-z0-9_]+$/ && NF>=3 {print $1}')
  up=$(printf '%s\n' "$all" | grep -c '|')
  sec=$(printf '%s\n' "$secset" | grep -c .)
  printf 'COUNTS|%s|%s\n' "$up" "$sec"
  printf '%s\n' "$all" | while IFS='|' read -r name ver; do
    [ -n "$name" ] || continue
    s=0; printf '%s\n' "$secset" | grep -qxF "$name" && s=1
    printf 'PKG|%s|%s|%s\n' "$name" "$ver" "$s"
  done
fi`
	out, err := runCmd(conn, cmd)
	if err != nil {
		return
	}
	var gotCounts bool
	pkgs := []models.PendingUpdate{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "COUNTS|"):
			f := strings.Split(line, "|")
			if len(f) < 3 {
				continue
			}
			if t, terr := strconv.Atoi(strings.TrimSpace(f[1])); terr == nil {
				inv.UpdatesAvailable = &t
				gotCounts = true
			}
			if s, serr := strconv.Atoi(strings.TrimSpace(f[2])); serr == nil {
				inv.SecurityUpdates = &s
			}
		case strings.HasPrefix(line, "PKG|"):
			f := strings.Split(line, "|")
			if len(f) < 4 || f[1] == "" {
				continue
			}
			if len(pkgs) < updatePackagesCap {
				pkgs = append(pkgs, models.PendingUpdate{
					Package: f[1], NewVersion: f[2], Security: strings.TrimSpace(f[3]) == "1",
				})
			}
		}
	}
	if !gotCounts {
		return // package manager not found / no parseable output — preserve last known
	}
	now := time.Now()
	inv.UpdatesCheckedAt = &now
	inv.UpdatePackages = pkgs
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
