package vulnscan

import (
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/winrm"
)

// A Windows scan run without the MSRC mapping reports a host as clean.
//
// Windows findings are the CVEs remediated by a host's missing security updates,
// resolved KB -> CVE -> severity through MSRC. With no mapping imported the scan still
// completes: the missing KBs are reported, with no CVEs, severity Unknown, and so zero
// critical, zero high, zero medium.
//
// Measured on a real Windows Server 2025 host with two missing security updates:
//
//	MSRC not imported:  total 2    critical 0  high 0
//	MSRC imported:      total 681  critical 63 high 618
//
// Same host, same moment. The first result reads as two minor issues; it was 63
// critical vulnerabilities with the assessment simply not performed, and nothing in
// the scan said so. "0 critical" was the absence of data rendered as good news.
func TestAnUnmappedWindowsScanSaysItCouldNotAssess(t *testing.T) {
	updates := []winrm.UpdateInfo{
		{KB: "KB5122871", Title: "2026-09 Security Update", Security: true},
		{KB: "KB5126052", Title: "2026-09 .NET Framework Security Update", Security: true},
	}
	// No MSRC entries for either KB: what an instance that has never imported the
	// mapping looks like.
	empty := map[string][]models.MSRCEntry{}

	unmapped := 0
	for _, u := range updates {
		if len(msrcEntriesFor(u, empty)) == 0 && (u.Security || u.Severity != "" || len(u.CVEs) > 0) {
			unmapped++
		}
	}
	if unmapped != len(updates) {
		t.Fatalf("expected all %d updates to be unmapped, got %d", len(updates), unmapped)
	}

	w := windowsWarning(unmapped)
	if w == "" {
		t.Fatal("a scan that could not match a single security update to a CVE reported " +
			"no warning: its zero critical / zero high totals would be read as a healthy host")
	}
	for _, want := range []string{"2", "msrc", "not counted"} {
		if !strings.Contains(strings.ToLower(w), want) {
			t.Errorf("the warning does not mention %q, so a reader cannot tell how much "+
				"of the result is missing:\n%s", want, w)
		}
	}
}

// And a fully mapped scan says nothing, so the warning keeps its meaning.
func TestAFullyMappedWindowsScanCarriesNoWarning(t *testing.T) {
	if w := windowsWarning(0); w != "" {
		t.Errorf("a scan that assessed everything still warned: %q", w)
	}
}
