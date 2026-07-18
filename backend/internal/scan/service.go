// Package scan runs OpenSCAP (oscap) security/compliance scans against managed
// hosts over the backend's SSH gateway, stores the HTML report, and parses a
// pass/fail summary. The backend is the sole SSH client (as everywhere else):
// it dials through the jump host as the privileged `fleet` account and runs
// oscap under sudo.
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/identity"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/sshgw"
	"github.com/fleet-terminal/backend/internal/store"
)

const (
	defaultScanTimeout = 60 * time.Minute
	minScanTimeout     = 5 * time.Minute
	maxScanTimeout     = 8 * time.Hour
)

// scanTimeout resolves the scan/remediation budget. Precedence: the `scan_policy`
// setting (timeoutMinutes, editable in the UI) overrides FLEET_SCAN_TIMEOUT,
// which overrides the built-in default. Clamped to a sane range.
func (s *Service) scanTimeout() time.Duration {
	d := defaultScanTimeout
	if s.cfg != nil && s.cfg.ScanTimeout > 0 {
		d = s.cfg.ScanTimeout
	}
	rctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if raw, err := s.store.GetSetting(rctx, "scan_policy"); err == nil {
		var sp struct {
			TimeoutMinutes int `json:"timeoutMinutes"`
		}
		if json.Unmarshal(raw, &sp) == nil && sp.TimeoutMinutes > 0 {
			d = time.Duration(sp.TimeoutMinutes) * time.Minute
		}
	}
	if d < minScanTimeout {
		d = minScanTimeout
	}
	if d > maxScanTimeout {
		d = maxScanTimeout
	}
	return d
}

// profileIDRe guards the profile id we interpolate into the remote shell.
var profileIDRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]*$`)

// ExpensiveFSRules are SSG rules whose checks recursively walk the filesystem
// (home directories, world-writable/SUID/SGID/unowned files). On hosts with many
// files they dominate scan time, so they're offered as a one-click skip.
var ExpensiveFSRules = []string{
	"xccdf_org.ssgproject.content_rule_accounts_users_home_files_permissions",
	"xccdf_org.ssgproject.content_rule_accounts_users_home_files_ownership",
	"xccdf_org.ssgproject.content_rule_accounts_users_home_files_groupownership",
	"xccdf_org.ssgproject.content_rule_file_permissions_unauthorized_world_writable",
	"xccdf_org.ssgproject.content_rule_file_permissions_unauthorized_suid",
	"xccdf_org.ssgproject.content_rule_file_permissions_unauthorized_sgid",
	"xccdf_org.ssgproject.content_rule_dir_perms_world_writable_sticky_bits",
	"xccdf_org.ssgproject.content_rule_no_files_unowned_by_user",
	"xccdf_org.ssgproject.content_rule_file_permissions_ungroupowned",
}

// Service orchestrates scans. It mirrors the monitor: a system signer maps to
// the privileged host account, dialed through the jump host.
type Service struct {
	store  *store.Store
	cfg    *config.Config
	log    *slog.Logger
	gw     *sshgw.Gateway
	issuer *identity.Issuer
	nfy    *notify.Service

	// installing tracks hosts with an in-flight background scanner install, so
	// repeated "prepare" requests don't kick off duplicate installs.
	installing sync.Map // hostID -> struct{}

	// contentMu serializes the one-time download+extract of the SCAP content
	// release into the backend cache.
	contentMu sync.Mutex
}

func New(st *store.Store, cfg *config.Config, log *slog.Logger, gw *sshgw.Gateway, issuer *identity.Issuer, nfy *notify.Service) *Service {
	return &Service{store: st, cfg: cfg, log: log, gw: gw, issuer: issuer, nfy: nfy}
}

// dial opens a privileged connection to the host, trying its candidate
// addresses in turn (WireGuard overlay first, then management address/hostname).
func (s *Service) dial(ctx context.Context, h *models.Host) (*sshgw.Conn, error) {
	signer, err := s.issuer.SystemSigner(ctx, s.issuer.SystemHostPrincipals(h.ID), 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("system signer: %w", err)
	}
	var lastErr error
	for _, addr := range dedupe([]string{h.WGAddress, h.Address, h.Hostname}) {
		conn, derr := s.gw.DialWithSigner(ctx, signer, addr, h.SSHPort, h.SSHUser)
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no reachable address")
	}
	return nil, lastErr
}

// DiscoverProfiles reports whether the host already has oscap + SCAP content and,
// if so, the available profiles for its datastream. It never installs anything
// (kept fast for opening the scan dialog); the scan itself auto-installs.
// exact reports whether the resolved datastream matches the host's exact OS
// version (vs a fallback); when false the host can be auto-provisioned.
func (s *Service) DiscoverProfiles(ctx context.Context, h *models.Host) (installed, exact bool, datastream string, profiles []models.ScanProfile, err error) {
	conn, err := s.dial(ctx, h)
	if err != nil {
		return false, false, "", nil, err
	}
	defer conn.Close()
	out, err := runScript(ctx, conn, discoverScript)
	if err != nil {
		return false, false, "", nil, err
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "STATUS="):
			if v := strings.TrimPrefix(line, "STATUS="); v != "ok" {
				return false, false, "", nil, nil // missing scanner or content
			}
			installed = true
		case strings.HasPrefix(line, "DATASTREAM="):
			datastream = strings.TrimPrefix(line, "DATASTREAM=")
		case strings.HasPrefix(line, "EXACT="):
			exact = strings.TrimPrefix(line, "EXACT=") == "1"
		case strings.Contains(line, ":") && strings.HasPrefix(line, "xccdf_"):
			id, title, _ := strings.Cut(line, ":")
			profiles = append(profiles, models.ScanProfile{ID: strings.TrimSpace(id), Title: strings.TrimSpace(title)})
		}
	}
	return installed, exact, datastream, profiles, nil
}

// IsInstalling reports whether a background scanner install is in flight for the host.
func (s *Service) IsInstalling(hostID uuid.UUID) bool {
	_, ok := s.installing.Load(hostID)
	return ok
}

// EnsureInstalled installs the scanner + SCAP content on the host in the
// background if not already running, so the profile picker can populate before
// the first scan (a sync request can't wait out a multi-minute package install).
// Idempotent: the install script is a no-op when oscap + content are present.
func (s *Service) EnsureInstalled(h *models.Host) {
	if _, loaded := s.installing.LoadOrStore(h.ID, struct{}{}); loaded {
		return // already installing
	}
	go func() {
		defer s.installing.Delete(h.ID)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		conn, err := s.dial(ctx, h)
		if err != nil {
			s.log.Warn("scan prepare: dial", "host", h.Hostname, "err", err)
			return
		}
		defer conn.Close()
		if _, err := runScript(ctx, conn, installScript); err != nil {
			s.log.Warn("scan prepare: install", "host", h.Hostname, "err", err)
			return
		}
		s.ensureContent(ctx, conn, h) // provision content matching the host OS version
		s.log.Info("scan prepare: scanner ready", "host", h.Hostname)
	}()
}

// Run executes a scan in the background and records its outcome. skipRules are
// rule ids excluded from the evaluation (oscap --skip-rule). It is launched in
// its own goroutine by the handler; ctx should be detached (context.Background).
func (s *Service) Run(scanID uuid.UUID, h *models.Host, profile string, skipRules []string) {
	ctx, cancel := context.WithTimeout(context.Background(), s.scanTimeout())
	defer cancel()

	fail := func(msg string) {
		s.log.Warn("host scan failed", "host", h.Hostname, "scan", scanID, "err", msg)
		// Record the failure with a fresh context — the main one may have expired.
		fctx, fcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer fcancel()
		_ = s.store.FailHostScan(fctx, scanID, msg)
	}

	if !profileIDRe.MatchString(profile) {
		fail("invalid profile id")
		return
	}
	conn, err := s.dial(ctx, h)
	if err != nil {
		fail("connect: " + err.Error())
		return
	}
	defer conn.Close()

	// Make sure the host has content matching its OS version before evaluating.
	s.ensureContent(ctx, conn, h)

	// Host-side oscap budget: a minute under Fleet's session timeout so oscap is
	// killed cleanly on the host (and reports rc 124) before the SSH session is
	// torn down — avoiding an orphaned oscap that keeps a core pegged.
	hostBudget := int(s.scanTimeout().Seconds()) - 60
	if hostBudget < 60 {
		hostBudget = 60
	}
	// Build the (validated) --skip-rule arguments for excluded rules.
	var skip strings.Builder
	for _, r := range skipRules {
		if ruleIDRe.MatchString(r) {
			skip.WriteString("--skip-rule ")
			skip.WriteString(r)
			skip.WriteString(" ")
		}
	}
	out, err := runScript(ctx, conn, fmt.Sprintf(scanScript, hostBudget, strings.TrimSpace(skip.String()), profile))
	if err != nil {
		fail("run oscap: " + err.Error())
		return
	}

	head, body, ok := strings.Cut(out, reportDelimiter)
	meta := parseKV(head)
	if status := meta["STATUS"]; status != "ok" {
		if status == "" {
			status = "scan produced no result"
		}
		// Surface oscap's own output (captured on failure) so the cause is visible.
		if detail := extractBlock(head, "DETAIL_BEGIN", "DETAIL_END"); detail != "" {
			status += " — " + strings.ReplaceAll(detail, "\n", " | ")
		}
		fail("oscap: " + status)
		return
	}
	report, results, _ := strings.Cut(body, resultsDelimiter)
	report = strings.TrimLeft(report, "\r\n")
	results = strings.TrimLeft(results, "\r\n")
	if !ok || strings.TrimSpace(report) == "" {
		fail("oscap produced no report")
		return
	}

	if err := s.store.StartHostScan(ctx, scanID, meta["PROFILE"], meta["PROFILE_TITLE"], meta["DATASTREAM"]); err != nil {
		s.log.Warn("host scan start record", "scan", scanID, "err", err)
	}

	if err := os.MkdirAll(s.cfg.ScanDir, 0o750); err != nil {
		fail("store report: " + err.Error())
		return
	}
	reportPath := filepath.Join(s.cfg.ScanDir, scanID.String()+".html")
	if err := os.WriteFile(reportPath, []byte(report), 0o640); err != nil {
		fail("write report: " + err.Error())
		return
	}
	resultsPath := ""
	if strings.TrimSpace(results) != "" {
		resultsPath = filepath.Join(s.cfg.ScanDir, scanID.String()+".results.xml")
		if err := os.WriteFile(resultsPath, []byte(results), 0o640); err != nil {
			s.log.Warn("write results xml", "scan", scanID, "err", err)
			resultsPath = ""
		}
	}

	pass, failCnt, other := atoi(meta["PASS"]), atoi(meta["FAIL"]), atoi(meta["OTHER"])
	sum := store.ScanSummary{
		PassCount: pass, FailCount: failCnt, OtherCount: other,
		TotalRules: pass + failCnt + other, ReportPath: reportPath, ResultsPath: resultsPath,
		SkipRules: skipRules,
	}
	if v, perr := strconv.ParseFloat(strings.TrimSpace(meta["SCORE"]), 64); perr == nil {
		sum.Score = &v
	}
	if err := s.store.CompleteHostScan(ctx, scanID, sum); err != nil {
		fail("record results: " + err.Error())
		return
	}
	s.log.Info("host scan completed", "host", h.Hostname, "scan", scanID,
		"profile", meta["PROFILE"], "pass", pass, "fail", failCnt)

	if failCnt > 0 && s.nfy != nil {
		s.nfy.Notify(context.Background(), notify.Event{
			Type: notify.EventScanFindings, Severity: notify.SeverityWarning,
			Title: fmt.Sprintf("Scan found %d failed rule(s) on %s", failCnt, h.Hostname),
			Body: fmt.Sprintf("OpenSCAP scan of %s (profile %s) finished: %d passed, %d failed, %d other.",
				h.Hostname, meta["PROFILE"], pass, failCnt, other),
			DedupeKey: h.ID.String(),
		})
	}
}

// --- remote scripts ---

const reportDelimiter = "=====FLEET_REPORT_HTML_BEGIN====="
const resultsDelimiter = "=====FLEET_RESULTS_XML_BEGIN====="

const discoverScript = `C=/usr/share/xml/scap/ssg/content
command -v oscap >/dev/null 2>&1 || { echo "STATUS=missing"; exit 0; }
ID=$(. /etc/os-release 2>/dev/null; echo "$ID"); VER=$(. /etc/os-release 2>/dev/null; echo "$VERSION_ID" | tr -d .)
DS=""
for c in "$C/ssg-${ID}${VER}-ds.xml" "$C/ssg-${ID}-ds.xml"; do [ -f "$c" ] && DS="$c" && break; done
[ -z "$DS" ] && DS=$(ls "$C"/ssg-${ID}*-ds.xml 2>/dev/null | sort -rV | head -1)
[ -z "$DS" ] && DS=$(ls "$C"/ssg-*-ds.xml 2>/dev/null | sort -rV | head -1)
[ -z "$DS" ] && { echo "STATUS=nocontent"; exit 0; }
echo "STATUS=ok"
echo "DATASTREAM=$DS"
[ -f "$C/ssg-${ID}${VER}-ds.xml" ] && echo "EXACT=1" || echo "EXACT=0"
oscap info --profiles "$DS" 2>/dev/null`

// installScript installs the scanner + SCAP content if missing (the install
// portion of scanScript, run standalone by EnsureInstalled). No-op when present.
const installScript = `C=/usr/share/xml/scap/ssg/content
if ! command -v oscap >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openscap-scanner >/dev/null 2>&1;
  elif command -v dnf >/dev/null 2>&1; then sudo dnf install -y openscap-scanner >/dev/null 2>&1;
  elif command -v yum >/dev/null 2>&1; then sudo yum install -y openscap-scanner >/dev/null 2>&1;
  elif command -v zypper >/dev/null 2>&1; then sudo zypper --non-interactive install openscap-utils >/dev/null 2>&1; fi
fi
if ! ls "$C"/ssg-*-ds.xml >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ssg-base ssg-debian ssg-debderived ssg-nondebian ssg-applications >/dev/null 2>&1 || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq scap-security-guide >/dev/null 2>&1;
  elif command -v dnf >/dev/null 2>&1; then sudo dnf install -y scap-security-guide >/dev/null 2>&1;
  elif command -v yum >/dev/null 2>&1; then sudo yum install -y scap-security-guide >/dev/null 2>&1;
  elif command -v zypper >/dev/null 2>&1; then sudo zypper --non-interactive install scap-security-guide >/dev/null 2>&1; fi
fi
# Debian/Ubuntu lack oscap's global CPE dictionary; provide an empty valid one
# (real platform detection comes from the SSG datastream). Guarded for distros
# that already ship it.
if command -v oscap >/dev/null 2>&1 && [ ! -f /usr/share/openscap/cpe/openscap-cpe-dict.xml ]; then sudo mkdir -p /usr/share/openscap/cpe 2>/dev/null; printf '<?xml version="1.0" encoding="UTF-8"?>\n<cpe-list xmlns="http://cpe.mitre.org/dictionary/2.0"/>\n' | sudo tee /usr/share/openscap/cpe/openscap-cpe-dict.xml >/dev/null 2>&1; fi
echo done`

// scanScript installs oscap + SCAP content if missing, resolves the host's
// datastream, evaluates the given profile (empty -> the standard profile), and
// prints a key/value summary followed by the HTML report after the delimiter.
// %d is the host-side oscap time budget (seconds); the first %s is the
// (validated) --skip-rule arguments; the second %s is the validated profile id.
// No `set -e`: oscap returns 2 when rules fail.
const scanScript = `TMO=%d
SKIP='%s'
C=/usr/share/xml/scap/ssg/content
if ! command -v oscap >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openscap-scanner >/dev/null 2>&1;
  elif command -v dnf >/dev/null 2>&1; then sudo dnf install -y openscap-scanner >/dev/null 2>&1;
  elif command -v yum >/dev/null 2>&1; then sudo yum install -y openscap-scanner >/dev/null 2>&1;
  elif command -v zypper >/dev/null 2>&1; then sudo zypper --non-interactive install openscap-utils >/dev/null 2>&1; fi
fi
if ! ls "$C"/ssg-*-ds.xml >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ssg-base ssg-debian ssg-debderived ssg-nondebian ssg-applications >/dev/null 2>&1 || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq scap-security-guide >/dev/null 2>&1;
  elif command -v dnf >/dev/null 2>&1; then sudo dnf install -y scap-security-guide >/dev/null 2>&1;
  elif command -v yum >/dev/null 2>&1; then sudo yum install -y scap-security-guide >/dev/null 2>&1;
  elif command -v zypper >/dev/null 2>&1; then sudo zypper --non-interactive install scap-security-guide >/dev/null 2>&1; fi
fi
command -v oscap >/dev/null 2>&1 || { echo "STATUS=scanner_unavailable"; exit 0; }
# Debian/Ubuntu don't ship oscap's global CPE dictionary; without it oscap can't
# confirm the platform (every rule -> notapplicable) and aborts (SIGABRT) at the
# end. An empty valid dict is enough — real platform detection comes from the SSG
# datastream. Guarded so distros that ship it (RHEL etc.) are untouched.
if [ ! -f /usr/share/openscap/cpe/openscap-cpe-dict.xml ]; then sudo mkdir -p /usr/share/openscap/cpe 2>/dev/null; printf '<?xml version="1.0" encoding="UTF-8"?>\n<cpe-list xmlns="http://cpe.mitre.org/dictionary/2.0"/>\n' | sudo tee /usr/share/openscap/cpe/openscap-cpe-dict.xml >/dev/null 2>&1; fi
ID=$(. /etc/os-release 2>/dev/null; echo "$ID"); VER=$(. /etc/os-release 2>/dev/null; echo "$VERSION_ID" | tr -d .)
DS=""
for c in "$C/ssg-${ID}${VER}-ds.xml" "$C/ssg-${ID}-ds.xml"; do [ -f "$c" ] && DS="$c" && break; done
[ -z "$DS" ] && DS=$(ls "$C"/ssg-${ID}*-ds.xml 2>/dev/null | sort -rV | head -1)
[ -z "$DS" ] && DS=$(ls "$C"/ssg-*-ds.xml 2>/dev/null | sort -rV | head -1)
[ -z "$DS" ] && { echo "STATUS=no_content"; exit 0; }
PROFILE='%s'
if [ -z "$PROFILE" ]; then
  PROFILE=$(oscap info --profiles "$DS" 2>/dev/null | grep -iE 'profile_standard' | head -1 | cut -d: -f1)
  [ -z "$PROFILE" ] && PROFILE=$(oscap info --profiles "$DS" 2>/dev/null | head -1 | cut -d: -f1)
fi
[ -z "$PROFILE" ] && { echo "STATUS=no_profile"; exit 0; }
PT=$(oscap info --profiles "$DS" 2>/dev/null | grep -F "$PROFILE:" | head -1 | cut -d: -f2-)
R=/tmp/fleet-scan-$$
sudo timeout "$TMO" oscap xccdf eval $SKIP --profile "$PROFILE" --results "$R-results.xml" --report "$R-report.html" "$DS" >"$R-out.log" 2>&1
RC=$?
if [ $RC -ne 0 ] && [ $RC -ne 2 ]; then
  echo "STATUS=eval_failed_rc_$RC"
  echo "DATASTREAM=$DS"
  echo "PROFILE=$PROFILE"
  echo "DETAIL_BEGIN"
  tail -c 1500 "$R-out.log" 2>/dev/null | tr -d '\r'
  echo ""
  echo "DETAIL_END"
  sudo rm -f "$R-results.xml" "$R-report.html" "$R-out.log" 2>/dev/null
  exit 0
fi
sudo rm -f "$R-out.log" 2>/dev/null
sudo chmod 0644 "$R-results.xml" "$R-report.html" 2>/dev/null
PASS=$(grep -c '<result>pass</result>' "$R-results.xml" 2>/dev/null || echo 0)
FAIL=$(grep -c '<result>fail</result>' "$R-results.xml" 2>/dev/null || echo 0)
ERR=$(grep -c '<result>error</result>' "$R-results.xml" 2>/dev/null || echo 0)
OTH=$(grep -cE '<result>(notapplicable|notchecked|notselected|informational|unknown|fixed)</result>' "$R-results.xml" 2>/dev/null || echo 0)
SCORE=$(grep -oE '<score[^>]*>[0-9.]+</score>' "$R-results.xml" | head -1 | grep -oE '[0-9.]+' | tail -1)
echo "STATUS=ok"
echo "DATASTREAM=$DS"
echo "PROFILE=$PROFILE"
echo "PROFILE_TITLE=$PT"
echo "SCORE=$SCORE"
echo "PASS=$PASS"
echo "FAIL=$FAIL"
echo "OTHER=$((ERR+OTH))"
echo "` + reportDelimiter + `"
cat "$R-report.html"
echo "` + resultsDelimiter + `"
cat "$R-results.xml"
sudo rm -f "$R-results.xml" "$R-report.html" 2>/dev/null`

// --- helpers ---

// maxScanOutput bounds how much oscap output is read into memory. A legitimate
// HTML report + results XML is large but well under this; the cap stops a
// misbehaving or hostile host from returning gigabytes and OOMing the backend.
const maxScanOutput = 64 << 20 // 64 MiB

// limitedBuffer accumulates output up to limit bytes, then discards the rest and
// records that truncation happened. It always reports a full write so the SSH
// session doesn't error mid-stream.
type limitedBuffer struct {
	limit     int
	buf       []byte
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
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

// runScript runs a /bin/sh script over the connection, respecting ctx by killing
// the session if it is cancelled (e.g. scan timeout). Output is capped at
// maxScanOutput; exceeding it fails the scan rather than returning untrustworthy
// partial output.
func runScript(ctx context.Context, conn *sshgw.Conn, script string) (string, error) {
	sess, err := conn.Client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out := &limitedBuffer{limit: maxScanOutput}
	sess.Stdout = out
	sess.Stderr = out
	done := make(chan error, 1)
	go func() { done <- sess.Run(script) }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return "", ctx.Err()
	case rerr := <-done:
		if out.truncated {
			return "", fmt.Errorf("scan output exceeded %d bytes", maxScanOutput)
		}
		return string(out.buf), rerr
	}
}

// extractBlock returns the text between the begin and end markers, trimmed.
func extractBlock(s, begin, end string) string {
	i := strings.Index(s, begin)
	if i < 0 {
		return ""
	}
	rest := s[i+len(begin):]
	if j := strings.Index(rest, end); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

func parseKV(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if k, v, ok := strings.Cut(line, "="); ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
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
