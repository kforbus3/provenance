package vulnscan

import (
	"testing"

	"github.com/kforbus3/Moorgate/backend/internal/models"
)

// A CVE that hits several binary packages from one source package is ONE
// vulnerability. Counting finding rows inflated every total (~2.1x on a stock
// debian:12) and made the roll-up a package-count leaderboard.
func TestSummarizeCountsDistinctCVEs(t *testing.T) {
	findings := []models.VulnFinding{
		{CVE: "CVE-1", Package: "libc6", Severity: "High", CVSSScore: 7.5, FixState: models.FixStateNotFixed},
		{CVE: "CVE-1", Package: "libc-bin", Severity: "High", CVSSScore: 7.5, FixState: models.FixStateNotFixed},
		{CVE: "CVE-1", Package: "libc-dev-bin", Severity: "High", CVSSScore: 7.5, FixState: models.FixStateNotFixed},
		{CVE: "CVE-2", Package: "perl-base", Severity: "Medium", CVSSScore: 5.0, FixState: models.FixStateWontFix},
	}
	sum, out := summarize(findings)
	if sum.Total != 2 {
		t.Errorf("Total = %d, want 2 distinct CVEs (from %d findings)", sum.Total, len(findings))
	}
	if sum.High != 1 || sum.Medium != 1 {
		t.Errorf("severity split = high %d / medium %d, want 1 / 1", sum.High, sum.Medium)
	}
	if sum.WontFix != 1 {
		t.Errorf("WontFix = %d, want 1", sum.WontFix)
	}
	// The drill-down must keep every affected package.
	if len(out) != len(findings) {
		t.Errorf("returned %d findings, want all %d preserved", len(out), len(findings))
	}
}

// If any one package has a fix, the CVE is actionable — it must not be buried by
// the packages that report wont-fix.
func TestSummarizeTakesMostActionableFixState(t *testing.T) {
	sum, _ := summarize([]models.VulnFinding{
		{CVE: "CVE-1", Package: "a", Severity: "High", FixState: models.FixStateWontFix},
		{CVE: "CVE-1", Package: "b", Severity: "High", FixedVersion: "1.2.3", FixState: models.FixStateFixed},
	})
	if sum.Fixable != 1 {
		t.Errorf("Fixable = %d, want 1", sum.Fixable)
	}
	if sum.WontFix != 0 {
		t.Errorf("WontFix = %d, want 0 — a fix exists for this CVE", sum.WontFix)
	}
	if sum.Total != 1 {
		t.Errorf("Total = %d, want 1", sum.Total)
	}
}

// Worst severity and highest CVSS win when a CVE's rows disagree.
func TestSummarizeTakesWorstSeverity(t *testing.T) {
	sum, _ := summarize([]models.VulnFinding{
		{CVE: "CVE-1", Package: "a", Severity: "Low", CVSSScore: 3.1},
		{CVE: "CVE-1", Package: "b", Severity: "Critical", CVSSScore: 9.8},
	})
	if sum.Critical != 1 || sum.Low != 0 {
		t.Errorf("critical %d / low %d, want 1 / 0", sum.Critical, sum.Low)
	}
	if sum.MaxCVSS != 9.8 {
		t.Errorf("MaxCVSS = %v, want 9.8", sum.MaxCVSS)
	}
}

// Scans recorded before fix_state existed, and the Windows/MSRC path (where the
// "fixed version" is the remediating KB), carry no explicit state.
func TestSummarizeFallsBackToFixedVersion(t *testing.T) {
	sum, _ := summarize([]models.VulnFinding{
		{CVE: "CVE-1", Package: "KB5099536", FixedVersion: "KB5099536", Severity: "Critical"},
		{CVE: "CVE-2", Package: "openssl", Severity: "High"},
	})
	if sum.Fixable != 1 {
		t.Errorf("Fixable = %d, want 1 (KB counts as an available fix)", sum.Fixable)
	}
	if sum.WontFix != 0 {
		t.Errorf("WontFix = %d, want 0 (absent state is unknown, not wont-fix)", sum.WontFix)
	}
}

// The regression that motivated all of this: a fully-patched host reports plenty of
// findings but nothing actionable, and that must be legible in the summary.
func TestSummarizePatchedHostHasNothingActionable(t *testing.T) {
	sum, _ := summarize([]models.VulnFinding{
		{CVE: "CVE-1", Package: "perl-base", Severity: "Critical", CVSSScore: 10.0, FixState: models.FixStateWontFix},
		{CVE: "CVE-2", Package: "libc6", Severity: "High", CVSSScore: 8.1, FixState: models.FixStateNotFixed},
	})
	if sum.Fixable != 0 {
		t.Errorf("Fixable = %d, want 0", sum.Fixable)
	}
	if sum.WontFix != 1 || sum.Total != 2 {
		t.Errorf("WontFix %d / Total %d, want 1 / 2", sum.WontFix, sum.Total)
	}
}
