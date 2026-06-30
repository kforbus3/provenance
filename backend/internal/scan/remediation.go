package scan

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

var (
	ruleIDRe    = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)
	benchmarkRe = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)
	scriptDelim = "=====FLEET_FIX_SCRIPT====="
	outputDelim = "=====FLEET_FIX_OUTPUT====="
)

// Findings returns the failed rules from a completed scan's stored results.
func (s *Service) Findings(ctx context.Context, scanID uuid.UUID) ([]models.ScanFinding, error) {
	path, err := s.store.ScanResultsPath(ctx, scanID)
	if err != nil || path == "" {
		return nil, fmt.Errorf("no stored results for this scan (re-run the scan)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseFailedFindings(string(data)), nil
}

// validateRules ensures every requested rule id is well-formed and was actually a
// failed rule in the scan; returns the access-impacting subset.
func validateRules(requested []string, findings []models.ScanFinding) (impacting []string, err error) {
	failed := map[string]bool{}
	risky := map[string]bool{}
	for _, f := range findings {
		failed[f.RuleID] = true
		risky[f.RuleID] = f.AccessImpacting
	}
	for _, r := range requested {
		if !ruleIDRe.MatchString(r) || !failed[r] {
			return nil, fmt.Errorf("unknown or invalid rule: %s", r)
		}
		if risky[r] {
			impacting = append(impacting, r)
		}
	}
	return impacting, nil
}

// PreviewFix returns the bash remediation that WOULD run for the selected rules,
// without applying anything (generates the fix on the host as a normal user).
func (s *Service) PreviewFix(ctx context.Context, scan *models.HostScan, host *models.Host, ruleIDs []string) (string, error) {
	if !profileIDRe.MatchString(scan.Profile) || !benchmarkRe.MatchString(scan.Benchmark) {
		return "", fmt.Errorf("scan is missing a usable profile/datastream")
	}
	conn, err := s.dial(ctx, host)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	out, err := runScript(ctx, conn, fmt.Sprintf(previewScript, scan.Benchmark, scan.Profile, strings.Join(ruleIDs, " "), scriptDelim))
	if err != nil {
		return "", err
	}
	head, script, ok := strings.Cut(out, scriptDelim)
	if meta := parseKV(head); meta["STATUS"] != "ok" {
		return "", fmt.Errorf("oscap could not generate fixes (scanner missing?)")
	}
	if !ok {
		return "", fmt.Errorf("no remediation produced")
	}
	return strings.TrimLeft(script, "\r\n"), nil
}

// Remediate applies fixes for the selected rules in the background, then re-scans
// to verify. The remediation record is updated with the outcome + re-scan id.
func (s *Service) Remediate(remID uuid.UUID, scan *models.HostScan, host *models.Host, ruleIDs []string, requestedBy *uuid.UUID, requester string) {
	// Covers apply + the synchronous verification re-scan (a full scan each).
	ctx, cancel := context.WithTimeout(context.Background(), 2*s.scanTimeout())
	defer cancel()
	failRem := func(msg string) {
		s.log.Warn("remediation failed", "host", host.Hostname, "rem", remID, "err", msg)
		_ = s.store.FailRemediation(ctx, remID, msg)
	}
	if !profileIDRe.MatchString(scan.Profile) || !benchmarkRe.MatchString(scan.Benchmark) {
		failRem("scan is missing a usable profile/datastream")
		return
	}
	conn, err := s.dial(ctx, host)
	if err != nil {
		failRem("connect: " + err.Error())
		return
	}
	defer conn.Close()
	s.ensureContent(ctx, conn, host)

	out, err := runScript(ctx, conn, fmt.Sprintf(applyScript, scan.Benchmark, scan.Profile, strings.Join(ruleIDs, " "), outputDelim))
	if err != nil {
		failRem("apply: " + err.Error())
		return
	}
	head, output, _ := strings.Cut(out, outputDelim)
	meta := parseKV(head)
	if meta["STATUS"] != "ok" {
		failRem("oscap: " + nonEmpty(meta["STATUS"], "no result"))
		return
	}
	rc := atoi(meta["RC"])
	output = strings.TrimLeft(output, "\r\n")

	// Verify with a fresh scan using the same profile.
	var rescanID *uuid.UUID
	if rec, err := s.store.CreateHostScan(ctx, host.ID, requestedBy, requester, scan.Profile, false); err == nil {
		// Reuse the original scan's skipped rules so the re-scan isn't slower.
		s.Run(rec.ID, host, scan.Profile, scan.SkipRules) // synchronous within this goroutine
		rescanID = &rec.ID
	} else {
		s.log.Warn("remediation rescan create", "err", err)
	}

	if err := s.store.CompleteRemediation(ctx, remID, rc, output, rescanID); err != nil {
		s.log.Warn("remediation complete record", "rem", remID, "err", err)
	}
	s.log.Info("remediation completed", "host", host.Hostname, "rem", remID, "rules", len(ruleIDs), "rc", rc)
}

func nonEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// previewScript generates (but does not run) bash fixes for the given rules.
// %s = datastream, profile, space-separated rule ids, script delimiter.
const previewScript = `DS='%s'
PROFILE='%s'
command -v oscap >/dev/null 2>&1 || { echo "STATUS=no_scanner"; exit 0; }
FIX=$(mktemp)
for RID in %s; do
  oscap xccdf generate fix --fix-type bash --profile "$PROFILE" --rule "$RID" "$DS" 2>/dev/null >> "$FIX"
done
echo "STATUS=ok"
echo "%s"
cat "$FIX"
rm -f "$FIX"`

// applyScript generates the fixes and runs them under sudo, capturing output + rc.
// %s = datastream, profile, space-separated rule ids, output delimiter.
const applyScript = `DS='%s'
PROFILE='%s'
command -v oscap >/dev/null 2>&1 || { echo "STATUS=no_scanner"; exit 0; }
FIX=$(mktemp); OUT=$(mktemp)
for RID in %s; do
  oscap xccdf generate fix --fix-type bash --profile "$PROFILE" --rule "$RID" "$DS" 2>/dev/null >> "$FIX"
done
sudo bash "$FIX" > "$OUT" 2>&1
RC=$?
echo "STATUS=ok"
echo "RC=$RC"
echo "%s"
cat "$OUT"
rm -f "$FIX" "$OUT"`
