package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/kforbus3/Moorgate/backend/internal/models"
)

// Compliance (OpenSCAP) coverage. Fleet runs two unrelated kinds of scan and an
// operator calls BOTH of them "the security scan":
//
//	compliance_scans  — OpenSCAP/SCAP benchmark evaluation (CIS/STIG): rules passed,
//	                    rules failed, a score. "Is this host built correctly?"
//	vulnerabilities   — Grype CVE matching against installed packages. "Is this host
//	                    running something with a known CVE?"
//
// Before this file the assistant could only roll CVEs up per host; compliance had
// one flat "recent_scans" recency list with no per-host view and no findings, so
// "the latest security scan result for each host" either answered from the wrong
// dataset or claimed no tool existed. Both are now first-class and the tool
// descriptions name the other one, so a mis-hit is one correction away.

// ---------------------------------------------------------------------------
// compliance_scans — latest OpenSCAP scan per host (or one host's history)
// ---------------------------------------------------------------------------

type complianceArgs struct {
	Hostname   string `json:"hostname"`
	FailedOnly bool   `json:"failedOnly"`
	Limit      int    `json:"limit"`
}

// runComplianceScans answers "what does compliance look like across the fleet" and
// "how did <host> score". With no hostname it returns ONE row per accessible host —
// that host's most recent scan, or a never-scanned marker — because the fleet-wide
// question is about coverage as much as scores: a host nobody has ever scanned is
// the finding, and a flat recency list hides it. With a hostname it returns that
// host's scan history so a trend ("is it improving?") is answerable.
func (s *Service) runComplianceScans(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	if !who.CanViewScans && !who.IsSuperAdmin {
		return nil, map[string]any{"error": "you do not have permission to view compliance scans"}
	}
	var a complianceArgs
	_ = json.Unmarshal(raw, &a)
	hostname := strings.TrimSpace(a.Hostname)

	if hostname != "" {
		return s.complianceForHost(ctx, hostname, a.Limit, who)
	}

	rows, err := s.store.LatestComplianceScansForAssistant(ctx, who.UserID, who.IsSuperAdmin)
	if err != nil {
		s.log.Warn("assistant compliance_scans", "err", err)
		return nil, map[string]any{"error": "could not read compliance scan results"}
	}
	kept := make([]models.AssistantComplianceRow, 0, len(rows))
	for _, r := range rows {
		// "Which hosts failed" means rules that failed OR a scan that errored out —
		// a scan that never produced a result is not a pass.
		if a.FailedOnly && r.FailCount == 0 && r.Status == "completed" {
			continue
		}
		kept = append(kept, r)
	}
	tbl := &AssistantTable{
		Title: "Compliance posture (latest scan per host)",
		Columns: []TableColumn{
			{Label: "Host"}, {Label: "Profile"}, {Label: "Score"}, {Label: "Passed"},
			{Label: "Failed"}, {Label: "Status"}, {Label: "Scanned", Kind: "time"},
		},
	}
	scanned, never, failing := 0, 0, 0
	for _, r := range kept {
		if r.NeverScanned {
			never++
			tbl.Rows = append(tbl.Rows, []string{r.Hostname, "", "", "", "", "never scanned", ""})
			continue
		}
		scanned++
		if r.FailCount > 0 {
			failing++
		}
		tbl.Rows = append(tbl.Rows, []string{
			r.Hostname, r.Profile, scoreLabel(r.Score),
			strconv.Itoa(r.PassCount), strconv.Itoa(r.FailCount),
			scanStatusLabel(r), tableTimePtr(r.FinishedAt),
		})
	}
	if len(tbl.Rows) == 0 {
		tbl = nil
	}
	return tbl, map[string]any{
		"kind":              "compliance (OpenSCAP benchmark)",
		"hostCount":         len(kept),
		"scannedHosts":      scanned,
		"neverScannedHost":  never,
		"hostsWithFailures": failing,
		"hosts":             kept,
	}
}

// complianceForHost returns one host's scan history, newest first.
func (s *Service) complianceForHost(ctx context.Context, hostname string, limit int, who Caller) (*AssistantTable, any) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	rows, err := s.store.RecentScansForAssistant(ctx, who.UserID, who.IsSuperAdmin, hostname, limit)
	if err != nil {
		s.log.Warn("assistant compliance_scans host", "err", err)
		return nil, map[string]any{"error": "could not read compliance scan results"}
	}
	if len(rows) == 0 {
		return nil, map[string]any{
			"kind": "compliance (OpenSCAP benchmark)", "host": hostname, "count": 0,
			"note": "no compliance scan has ever been run on " + hostname +
				" (this is about OpenSCAP benchmark scans, not CVE scans — those are the vulnerabilities tool)",
		}
	}
	tbl := &AssistantTable{
		Title: "Compliance scans — " + hostname,
		Columns: []TableColumn{
			{Label: "Scanned", Kind: "time"}, {Label: "Profile"}, {Label: "Score"},
			{Label: "Passed"}, {Label: "Failed"}, {Label: "Status"}, {Label: "Trigger"},
		},
	}
	for _, r := range rows {
		trigger := "manual"
		if r.Scheduled {
			trigger = "scheduled"
		}
		tbl.Rows = append(tbl.Rows, []string{
			tableTimePtr(r.FinishedAt), r.Profile, scoreLabel(r.Score),
			strconv.Itoa(r.PassCount), strconv.Itoa(r.FailCount), r.Status, trigger,
		})
	}
	payload := map[string]any{
		"kind": "compliance (OpenSCAP benchmark)", "host": hostname,
		"count": len(rows), "scans": rows,
	}
	// These rows are per-SCAN totals, not the rules themselves. Point the model at the
	// drill-down: "what rules is <host> failing" reaches this tool on phrasings the
	// deterministic router does not catch, and without the hint the model narrates the
	// counts as though they answered the question.
	if rows[0].FailCount > 0 {
		payload["nextStep"] = "these are per-scan totals; to answer WHICH rules failed on " +
			hostname + ", call scan_findings with hostname=" + hostname
	}
	return tbl, payload
}

// scoreLabel renders an XCCDF score for a table cell ("" when the scan never
// produced one, so a failed scan does not masquerade as a 0% score).
func scoreLabel(score *float64) string {
	if score == nil {
		return ""
	}
	return strconv.FormatFloat(round1(*score), 'f', -1, 64) + "%"
}

// scanStatusLabel keeps a non-completed scan's real state visible, since a failed or
// stuck scan is materially different from a clean result and both show 0 failures.
func scanStatusLabel(r models.AssistantComplianceRow) string {
	if r.Status == "completed" {
		return "completed"
	}
	if r.Error != "" {
		return r.Status + ": " + r.Error
	}
	return r.Status
}

// ---------------------------------------------------------------------------
// scan_findings — the failed rules of a host's latest compliance scan
// ---------------------------------------------------------------------------

type scanFindingsArgs struct {
	Hostname string `json:"hostname"`
	Severity string `json:"severity"`
	Limit    int    `json:"limit"`
}

// runScanFindings lists which RULES failed on a host's most recent completed
// compliance scan — the natural follow-up to "host X failed 41 rules". The rules
// are parsed from the stored scan results, so this answers only for a host whose
// report is still on disk.
func (s *Service) runScanFindings(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	if !who.CanViewScans && !who.IsSuperAdmin {
		return nil, map[string]any{"error": "you do not have permission to view compliance scans"}
	}
	var a scanFindingsArgs
	_ = json.Unmarshal(raw, &a)
	hostname := strings.TrimSpace(a.Hostname)
	if hostname == "" {
		return nil, map[string]any{"error": "hostname is required — failed rules are per host. For the fleet-wide picture use compliance_scans."}
	}
	if s.findings == nil {
		return nil, map[string]any{"error": "scan findings are not available on this server"}
	}
	scanID, err := s.store.LatestScanIDForHost(ctx, who.UserID, who.IsSuperAdmin, hostname)
	if err != nil {
		return nil, map[string]any{
			"host": hostname, "count": 0,
			"note": "no completed compliance scan for " + hostname + " (or you cannot access that host)",
		}
	}
	found, err := s.findings(ctx, scanID)
	if err != nil {
		s.log.Warn("assistant scan_findings", "host", hostname, "err", err)
		return nil, map[string]any{
			"host": hostname,
			"note": "the scan summary is available but its stored results are no longer on disk, so the individual failed rules cannot be listed (re-run the scan)",
		}
	}
	sev := strings.ToLower(strings.TrimSpace(a.Severity))
	limit := a.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	kept := make([]models.ScanFinding, 0, len(found))
	for _, f := range found {
		if sev != "" && !scapSeverityAtLeast(f.Severity, sev) {
			continue
		}
		kept = append(kept, f)
	}
	// Worst first, so a truncated list still leads with what matters.
	sort.SliceStable(kept, func(i, j int) bool {
		return scapSeverityRank(kept[i].Severity) > scapSeverityRank(kept[j].Severity)
	})
	if len(kept) > limit {
		kept = kept[:limit]
	}
	if len(kept) == 0 {
		return nil, map[string]any{
			"host": hostname, "count": 0, "severityFilter": sev,
			"note": "no failed rules matched on " + hostname + "'s latest compliance scan",
		}
	}
	tbl := &AssistantTable{
		Title:   "Failed compliance rules — " + hostname,
		Columns: []TableColumn{{Label: "Severity"}, {Label: "Rule"}, {Label: "Rule ID"}, {Label: "Risk"}},
	}
	impacting := 0
	for _, f := range kept {
		risk := ""
		if f.AccessImpacting {
			risk = "may cut Fleet's access"
			impacting++
		}
		tbl.Rows = append(tbl.Rows, []string{f.Severity, f.Title, f.RuleID, risk})
	}
	return tbl, map[string]any{
		"kind": "compliance (OpenSCAP benchmark) failed rules",
		"host": hostname, "count": len(kept), "severityFilter": sev,
		"accessImpactingCount": impacting,
		"accessImpactingNote": "rules flagged access-impacting could sever Fleet's own SSH/network path to the host if remediated; " +
			"report them as needing care, and never imply they have been or will be fixed automatically",
		"findings": kept,
	}
}

// scapSeverityRank orders SCAP severities so the worst failures sort first.
func scapSeverityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// scapSeverityAtLeast reports whether a finding's severity meets the requested floor.
func scapSeverityAtLeast(have, floor string) bool {
	return scapSeverityRank(have) >= scapSeverityRank(floor)
}

// ---------------------------------------------------------------------------
// deterministic answers
// ---------------------------------------------------------------------------

// compliancePostureDirectAnswer builds the fleet-wide compliance answer in code.
// The question ("the latest result for EACH host") is an enumeration over every
// host, and enumeration is exactly what a small local model gets wrong — it
// truncates, miscounts, and quietly drops the never-scanned hosts, which are the
// rows an operator most needs to see. Returns "" for anything but the fleet-wide
// roll-up, so per-host and follow-up questions keep model narration.
func compliancePostureDirectAnswer(payload any) string {
	m, ok := payload.(map[string]any)
	if !ok {
		return ""
	}
	rows, ok := m["hosts"].([]models.AssistantComplianceRow)
	if !ok || len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	scanned, never := 0, 0
	for _, r := range rows {
		if r.NeverScanned {
			never++
		} else {
			scanned++
		}
	}
	fmt.Fprintf(&b, "Latest compliance (OpenSCAP) scan for each of the %d hosts", len(rows))
	if never > 0 {
		fmt.Fprintf(&b, " — %d scanned, %d never scanned", scanned, never)
	}
	b.WriteString(":\n")
	for _, r := range rows {
		if r.NeverScanned {
			fmt.Fprintf(&b, "- %s: never scanned\n", r.Hostname)
			continue
		}
		if r.Status != "completed" {
			fmt.Fprintf(&b, "- %s: last scan %s\n", r.Hostname, scanStatusLabel(r))
			continue
		}
		fmt.Fprintf(&b, "- %s: %s failed, %d passed", r.Hostname, failedLabel(r.FailCount), r.PassCount)
		if r.Score != nil {
			fmt.Fprintf(&b, ", score %s", scoreLabel(r.Score))
		}
		if r.Profile != "" {
			fmt.Fprintf(&b, " (%s)", r.Profile)
		}
		if r.FinishedAt != nil {
			fmt.Fprintf(&b, " — %s", tableTimePtr(r.FinishedAt))
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func failedLabel(n int) string {
	if n == 1 {
		return "1 rule"
	}
	return strconv.Itoa(n) + " rules"
}
