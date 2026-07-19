// Package vulnscan runs vulnerability (CVE) scans of managed hosts. The backend
// collects a host's package databases over the SSH gateway and posts them to the
// grype-scanner sidecar, which matches them against a CVE database and returns
// findings with CVSS scores. This is distinct from the OpenSCAP compliance scans
// in internal/scan.
package vulnscan

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/credinject"
	"github.com/fleet-terminal/backend/internal/identity"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/sshgw"
	"github.com/fleet-terminal/backend/internal/store"
	"github.com/fleet-terminal/backend/internal/winrm"
)

// collectScript tars a host's package databases (only the paths that exist, so it
// works with any tar and on both dpkg and rpm systems) and base64-encodes them.
// Requires sudo to read the rpm database; the scan connection is privileged.
// The -h/--dereference flag follows symlinks so the archive holds only regular
// files: /etc/os-release is commonly a symlink (→ /usr/lib/os-release), and
// /var/lib/rpm is a symlink on some distros (openSUSE). The scanner sidecar
// refuses archives containing links (a path-traversal guard), so dereferencing
// here is required for those hosts to scan at all.
const collectScript = `set -e
FILES="etc/os-release"
[ -f /var/lib/dpkg/status ] && FILES="$FILES var/lib/dpkg/status"
[ -d /var/lib/rpm ] && FILES="$FILES var/lib/rpm"
sudo tar czhf - -C / $FILES 2>/dev/null | base64 | tr -d '\n'`

const maxCollectBytes = 128 << 20 // base64 of a host's package DBs; rpm DB can be a few MB

// Service runs vulnerability scans.
type Service struct {
	store  *store.Store
	cfg    *config.Config
	log    *slog.Logger
	gw     *sshgw.Gateway
	issuer *identity.Issuer
	nfy    *notify.Service
	client *http.Client
}

func New(st *store.Store, cfg *config.Config, log *slog.Logger, gw *sshgw.Gateway, issuer *identity.Issuer, nfy *notify.Service) *Service {
	return &Service{store: st, cfg: cfg, log: log, gw: gw, issuer: issuer, nfy: nfy,
		client: &http.Client{Timeout: 6 * time.Minute}}
}

// Run performs a scan in the background: collect package DBs over SSH, hand them
// to the sidecar, store the findings. Marks the scan failed on any error.
func (s *Service) Run(scanID uuid.UUID, h *models.Host) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	fail := func(msg string) {
		s.log.Warn("vuln scan failed", "host", h.Hostname, "err", msg)
		_ = s.store.FailVulnScan(ctx, scanID, msg)
	}
	if err := s.store.StartVulnScan(ctx, scanID); err != nil {
		fail("start: " + err.Error())
		return
	}

	// Windows (RDP) hosts have no SSH package databases and grype doesn't cover
	// Windows. Instead, a host's vulnerabilities are the CVEs remediated by its
	// missing security updates — collected over WinRM from the Windows Update Agent.
	if h.Protocol == "rdp" {
		findings, err := s.collectWindows(ctx, h)
		if err != nil {
			fail("collect windows updates: " + err.Error())
			return
		}
		sum, findings := summarize(findings)
		if err := s.store.CompleteVulnScan(ctx, scanID, sum, findings, nil); err != nil {
			fail("store findings: " + err.Error())
			return
		}
		s.log.Info("vuln scan completed (windows)", "host", h.Hostname, "total", sum.Total,
			"critical", sum.Critical, "high", sum.High)
		s.notify(ctx, h, sum)
		return
	}

	tarball, err := s.collect(ctx, h)
	if err != nil {
		fail("collect packages: " + err.Error())
		return
	}
	result, err := s.scanSidecar(ctx, tarball)
	if err != nil {
		fail(err.Error())
		return
	}

	sum, findings := summarize(result.Findings)
	var dbBuilt *time.Time
	if t, err := time.Parse(time.RFC3339, result.DBBuilt); err == nil {
		dbBuilt = &t
	}
	if err := s.store.CompleteVulnScan(ctx, scanID, sum, findings, dbBuilt); err != nil {
		fail("store findings: " + err.Error())
		return
	}
	s.log.Info("vuln scan completed", "host", h.Hostname, "total", sum.Total,
		"critical", sum.Critical, "high", sum.High, "maxCvss", sum.MaxCVSS)
	s.notify(ctx, h, sum)
}

// collect opens a privileged connection and pulls the host's package databases.
func (s *Service) collect(ctx context.Context, h *models.Host) ([]byte, error) {
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

	b64, err := runCapture(ctx, conn, collectScript)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("decode package archive: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("no package data collected (unsupported OS?)")
	}
	return raw, nil
}

// collectWindows scans a Windows host by enumerating its missing security updates
// over WinRM and turning each into vulnerability findings — one per CVE the update
// remediates (the host is exposed to those CVEs until it's installed). Authenticated
// with the host's open-policy vault credential (scans are unattended), tunneled
// through the jump host.
func (s *Service) collectWindows(ctx context.Context, h *models.Host) ([]models.VulnFinding, error) {
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
	user, pass, err := credinject.PasswordForSystem(ctx, s.store, key, h)
	if err != nil {
		return nil, fmt.Errorf("credential: %w", err)
	}
	cands := dedupe([]string{h.WGAddress, h.Address, h.Hostname})
	if len(cands) == 0 {
		return nil, fmt.Errorf("host has no address")
	}
	dial := func(_ /*network*/, addr string) (net.Conn, error) { return jump.DialContext(ctx, "tcp", addr) }

	updates, err := winrm.CollectUpdates(ctx, dial, cands[0], user, pass, s.cfg.RDPWinRMPorts, 5*time.Minute)
	if err != nil {
		return nil, err
	}

	var findings []models.VulnFinding
	seen := map[string]bool{}
	for _, u := range updates {
		// Only vulnerability-relevant updates: security category, an MSRC severity,
		// or a CVE list. Skip ordinary feature/driver updates.
		if !u.Security && u.Severity == "" && len(u.CVEs) == 0 {
			continue
		}
		sev := mapMsrcSeverity(u.Severity)
		base := models.VulnFinding{
			Package: u.KB, InstalledVersion: "not installed", FixedVersion: u.KB,
			Severity: sev, Description: u.Title,
		}
		if len(u.CVEs) == 0 {
			id := u.KB
			if id == "" {
				id = "update"
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			f := base
			f.CVE = id
			f.DataSource = kbURL(u.KB) // link the KB to its support page (CVE column links dataSource)
			findings = append(findings, f)
			continue
		}
		for _, cve := range u.CVEs {
			k := cve + "|" + u.KB
			if seen[k] {
				continue
			}
			seen[k] = true
			f := base
			f.CVE = cve
			f.DataSource = "https://msrc.microsoft.com/update-guide/vulnerability/" + cve
			findings = append(findings, f)
		}
	}
	return findings, nil
}

// kbURL builds the Microsoft support URL for a KB (the first, if several), so the
// finding links somewhere useful when it carries no CVE.
func kbURL(kb string) string {
	if i := strings.IndexByte(kb, ';'); i >= 0 {
		kb = kb[:i]
	}
	num := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(kb)), "KB")
	if num == "" {
		return ""
	}
	return "https://support.microsoft.com/help/" + num
}

// mapMsrcSeverity maps Microsoft's MSRC severity labels onto the grype-style severity
// buckets the summary and UI use, so Windows and Linux findings rank consistently.
func mapMsrcSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "Critical"
	case "important":
		return "High"
	case "moderate":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Unknown"
	}
}

type sidecarResult struct {
	Findings []models.VulnFinding `json:"findings"`
	DBBuilt  string               `json:"dbBuilt"`
}

// scanSidecar posts the package tarball to the grype-scanner and returns findings.
func (s *Service) scanSidecar(ctx context.Context, tarball []byte) (*sidecarResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url("/scan"), bytes.NewReader(tarball))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/gzip")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scanner unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if strings.Contains(strings.ToLower(msg), "no such") || strings.Contains(strings.ToLower(msg), "database") {
			return nil, fmt.Errorf("scanner error: %s (update or import the vulnerability database first)", truncate(msg, 300))
		}
		return nil, fmt.Errorf("scanner error (%d): %s", resp.StatusCode, truncate(msg, 300))
	}
	var out sidecarResult
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parse scanner response: %w", err)
	}
	return &out, nil
}

func (s *Service) notify(ctx context.Context, h *models.Host, sum store.VulnSummary) {
	if s.nfy == nil {
		return
	}
	sev := notify.SeverityInfo
	if sum.Critical > 0 || sum.High > 0 {
		sev = notify.SeverityWarning
	}
	s.nfy.Notify(ctx, notify.Event{
		Type: notify.EventScanFindings, Severity: sev,
		Title: fmt.Sprintf("Vulnerability scan: %s", h.Hostname),
		Body: fmt.Sprintf("Scan of %s found %d vulnerabilities (%d critical, %d high, %d medium). Highest CVSS %.1f.",
			h.Hostname, sum.Total, sum.Critical, sum.High, sum.Medium, sum.MaxCVSS),
		DedupeKey: h.ID.String(),
	})
}

func (s *Service) url(p string) string { return strings.TrimRight(s.cfg.GrypeScannerURL, "/") + p }

// --- DB management (proxied to the sidecar) ---

// DBStatus returns the scanner's vulnerability-DB status text.
func (s *Service) DBStatus(ctx context.Context) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.url("/db/status"), nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(b), nil
}

// DBUpdate triggers an online vulnerability-DB update on the sidecar.
func (s *Service) DBUpdate(ctx context.Context) (string, error) {
	return s.dbPost(ctx, "/db/update", nil, "application/json")
}

// DBImport uploads a pre-downloaded DB archive for offline/air-gapped import.
func (s *Service) DBImport(ctx context.Context, archive io.Reader) (string, error) {
	return s.dbPost(ctx, "/db/import", archive, "application/gzip")
}

func (s *Service) dbPost(ctx context.Context, path string, body io.Reader, contentType string) (string, error) {
	// DB operations can take minutes; use a dedicated longer-timeout client.
	client := &http.Client{Timeout: 20 * time.Minute}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url(path), body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("scanner unreachable: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r struct {
		OK     bool   `json:"ok"`
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	_ = json.Unmarshal(b, &r)
	if resp.StatusCode != http.StatusOK || !r.OK {
		msg := r.Error
		if msg == "" {
			msg = r.Output
		}
		return r.Output, fmt.Errorf("db operation failed: %s", truncate(msg, 400))
	}
	return r.Output, nil
}

// --- helpers ---

func summarize(findings []models.VulnFinding) (store.VulnSummary, []models.VulnFinding) {
	var sum store.VulnSummary
	sum.Total = len(findings)
	for _, f := range findings {
		if f.CVSSScore > sum.MaxCVSS {
			sum.MaxCVSS = f.CVSSScore
		}
		switch strings.ToLower(f.Severity) {
		case "critical":
			sum.Critical++
		case "high":
			sum.High++
		case "medium":
			sum.Medium++
		case "low":
			sum.Low++
		case "negligible":
			sum.Negligible++
		default:
			sum.Unknown++
		}
	}
	return sum, findings
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// runCapture runs a shell script over the connection, capturing bounded stdout,
// and killing the session if ctx is cancelled.
func runCapture(ctx context.Context, conn *sshgw.Conn, script string) (string, error) {
	sess, err := conn.Client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var buf capBuffer
	buf.limit = maxCollectBytes
	sess.Stdout = &buf
	done := make(chan error, 1)
	go func() { done <- sess.Run(script) }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return "", ctx.Err()
	case rerr := <-done:
		if buf.truncated {
			return "", fmt.Errorf("package data exceeded %d bytes", maxCollectBytes)
		}
		if rerr != nil {
			return "", fmt.Errorf("collect command failed: %w", rerr)
		}
		return string(buf.buf), nil
	}
}

// capBuffer accumulates output up to limit bytes.
type capBuffer struct {
	limit     int
	buf       []byte
	truncated bool
}

func (b *capBuffer) Write(p []byte) (int, error) {
	if room := b.limit - len(b.buf); room > 0 {
		if len(p) > room {
			b.buf = append(b.buf, p[:room]...)
			b.truncated = true
		} else {
			b.buf = append(b.buf, p...)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}
