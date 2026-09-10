package vulnscan

import (
	"fmt"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/models"
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

// The screenshot that started this: 1646 CVEs, 86 critical, 0 fixable. The raw
// severity counts cannot be the roll-up's headline, because on a patched host they
// measure exposure that no upgrade will ever clear. The fixable-scoped counts are
// what a reader needs, and they must read zero here while Critical stays at 86.
func TestSummarizeFixableSeverityIsZeroOnAPatchedHost(t *testing.T) {
	var findings []models.VulnFinding
	for i := 0; i < 86; i++ {
		findings = append(findings, models.VulnFinding{
			CVE: fmt.Sprintf("CVE-C-%d", i), Package: "libcpupower1", SourcePackage: "linux",
			Severity: "Critical", CVSSScore: 9.8, FixState: models.FixStateNotFixed,
		})
	}
	for i := 0; i < 461; i++ {
		findings = append(findings, models.VulnFinding{
			CVE: fmt.Sprintf("CVE-H-%d", i), Package: "libcpupower1", SourcePackage: "linux",
			Severity: "High", CVSSScore: 7.8, FixState: models.FixStateWontFix,
		})
	}
	sum, _ := summarize(findings)
	if sum.Critical != 86 || sum.High != 461 {
		t.Errorf("raw severity = %d critical / %d high, want 86 / 461 (exposure is still reported)",
			sum.Critical, sum.High)
	}
	if sum.FixableCritical != 0 || sum.FixableHigh != 0 {
		t.Errorf("fixable severity = %d critical / %d high, want 0 / 0 — nothing here has a fix",
			sum.FixableCritical, sum.FixableHigh)
	}
	if sum.FixableMaxCVSS != 0 {
		t.Errorf("FixableMaxCVSS = %v, want 0 when nothing is fixable", sum.FixableMaxCVSS)
	}
	// MaxCVSS is exactly the column this replaces: it reads 9.8 on a host with no
	// outstanding work, which is why it sorted and communicated nothing.
	if sum.MaxCVSS != 9.8 {
		t.Errorf("MaxCVSS = %v, want 9.8", sum.MaxCVSS)
	}
}

// Fixable severity counts the fixable subset only, and the worst FIXABLE score is
// not the worst score. A 10.0 nobody can fix must not set the number that is meant
// to say how urgent today's patching is.
func TestSummarizeFixableCountsExcludeUnfixable(t *testing.T) {
	sum, _ := summarize([]models.VulnFinding{
		{CVE: "CVE-1", Package: "perl-base", Severity: "Critical", CVSSScore: 10.0, FixState: models.FixStateWontFix},
		{CVE: "CVE-2", Package: "libssl3", Severity: "Critical", CVSSScore: 9.1, FixState: models.FixStateNotFixed},
		{CVE: "CVE-3", Package: "curl", Severity: "High", CVSSScore: 7.5, FixedVersion: "8.5.0-1", FixState: models.FixStateFixed},
		{CVE: "CVE-4", Package: "zlib1g", Severity: "Medium", CVSSScore: 5.3, FixedVersion: "1.3-1", FixState: models.FixStateFixed},
	})
	if sum.Critical != 2 {
		t.Errorf("Critical = %d, want 2", sum.Critical)
	}
	if sum.FixableCritical != 0 {
		t.Errorf("FixableCritical = %d, want 0 — neither critical has a fix", sum.FixableCritical)
	}
	if sum.FixableHigh != 1 || sum.FixableMedium != 1 {
		t.Errorf("fixable high %d / medium %d, want 1 / 1", sum.FixableHigh, sum.FixableMedium)
	}
	if sum.MaxCVSS != 10.0 {
		t.Errorf("MaxCVSS = %v, want 10.0", sum.MaxCVSS)
	}
	if sum.FixableMaxCVSS != 7.5 {
		t.Errorf("FixableMaxCVSS = %v, want 7.5 — the worst score you can actually act on", sum.FixableMaxCVSS)
	}
}

// A CVE fixable on one package and wont-fix on another is actionable, and must
// count into the fixable severity bucket too — not just the plain Fixable total.
func TestSummarizeFixableSeverityFollowsMostActionableState(t *testing.T) {
	sum, _ := summarize([]models.VulnFinding{
		{CVE: "CVE-1", Package: "libfoo", Severity: "Critical", CVSSScore: 9.8, FixState: models.FixStateWontFix},
		{CVE: "CVE-1", Package: "foo", Severity: "Critical", CVSSScore: 9.8, FixedVersion: "2.0", FixState: models.FixStateFixed},
	})
	if sum.Fixable != 1 || sum.FixableCritical != 1 {
		t.Errorf("Fixable %d / FixableCritical %d, want 1 / 1", sum.Fixable, sum.FixableCritical)
	}
	if sum.FixableMaxCVSS != 9.8 {
		t.Errorf("FixableMaxCVSS = %v, want 9.8", sum.FixableMaxCVSS)
	}
}
