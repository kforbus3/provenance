package assistant

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kforbus3/provenance/backend/internal/store"
)

// The bug: every question naming a CVE went to the fleet roll-up with the ID
// dropped, so Ask answered "I don't have that information" while the scans had it.
// Each of these must reach the vulnerabilities tool WITH the ID, and with the host
// only when the question is about one host.
func TestFastPathRoutesCVEQuestionsWithTheID(t *testing.T) {
	cases := []struct {
		q, cve, host string
	}{
		{"Are any hosts vulnerable to CVE-2024-6387?", "CVE-2024-6387", ""},
		{"which hosts are affected by cve-2024-3094", "CVE-2024-3094", ""},
		{"do we have CVE-2024-6387 anywhere", "CVE-2024-6387", ""},
		{"which hosts have CVE-2024-6387 on them", "CVE-2024-6387", ""},
		{"Is the fleet exposed to CVE-2021-44228?", "CVE-2021-44228", ""},
		{"are we vulnerable to CVE-2021-44228 on any host?", "CVE-2021-44228", ""},
		{"check every host for CVE-2023-4863", "CVE-2023-4863", ""},
		{"check for CVE-2023-4863", "CVE-2023-4863", ""}, // the ID is never a hostname
		{"do any scans show CVE-2024-6387?", "CVE-2024-6387", ""},
		{"is debian vulnerable to CVE-2023-4863?", "CVE-2023-4863", "debian"},
		{"Is web01 still affected by CVE-2024-6387", "CVE-2024-6387", "web01"},
		{"does nas have CVE-2024-6387?", "CVE-2024-6387", "nas"},
		{"is CVE-2024-6387 present on sshman?", "CVE-2024-6387", "sshman"},
		{"which hosts have CVE-2024-6387 or CVE-2024-3094?", "CVE-2024-6387,CVE-2024-3094", ""},
		{"any hosts affected by GHSA-49gw-vxvf-fc2g?", "GHSA-49GW-VXVF-FC2G", ""},
	}
	for _, c := range cases {
		name, raw, ok := fastPathTool(c.q)
		if !ok || name != "vulnerabilities" {
			t.Errorf("%q -> %q ok=%v, want vulnerabilities", c.q, name, ok)
			continue
		}
		var a vulnArgs
		if err := json.Unmarshal(raw, &a); err != nil {
			t.Fatal(err)
		}
		if a.CVE != c.cve || a.Hostname != c.host {
			t.Errorf("%q -> cve=%q host=%q, want cve=%q host=%q", c.q, a.CVE, a.Hostname, c.cve, c.host)
		}
	}
}

// Asking to RUN a scan for a CVE is an action, not a lookup; it must stay off the
// read fast path so the model can propose the scan.
func TestFastPathLeavesCVEScanRequestsToTheActionPath(t *testing.T) {
	for _, q := range []string{
		"scan web01 for CVE-2024-6387",
		"please rescan debian for CVE-2024-6387",
		"run a vulnerability scan on nas looking for CVE-2024-6387",
	} {
		if name, _, ok := fastPathTool(q); ok && name == "vulnerabilities" {
			t.Errorf("%q fast-pathed to the read tool", q)
		}
	}
	// ...but a leading "scan" followed by a read noun is still a read.
	if name, _, _ := fastPathTool("scan results for CVE-2024-6387?"); name != "vulnerabilities" {
		t.Errorf("scan-results question lost the read fast path: %q", name)
	}
	if name, _, _ := fastPathTool("scan web01 for vulnerabilities"); name == "vulnerabilities" {
		t.Errorf("generic scan request fast-pathed to the read tool")
	}
}

func TestVulnIDsFromText(t *testing.T) {
	got := vulnIDsFromText("cve-2024-6387, CVE-2024-6387 and GHSA-49gw-vxvf-fc2g; not CVE-24-1")
	want := []string{"CVE-2024-6387", "GHSA-49GW-VXVF-FC2G"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func cveResult(host string, e *store.CVEExposure) *cveExposureResult {
	return &cveExposureResult{IDs: []string{"CVE-2024-6387"}, Host: host, Exp: e, Fix: map[string]string{}}
}

func TestCVEAnswerListsEveryAffectedHostAndTheCoverage(t *testing.T) {
	old := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	e := &store.CVEExposure{
		Hosts: []store.CVEHostMatch{
			{Hostname: "alpha", ID: "CVE-2024-6387", Package: "openssh-server", InstalledVersion: "1:9.2p1-2", FixedVersion: "1:9.2p1-2+deb12u3", Severity: "High"},
			{Hostname: "beta", ID: "CVE-2024-6387", Package: "openssh-server", InstalledVersion: "1:9.2p1-2", FixState: "wont-fix", Severity: "High"},
		},
		Containers: []store.CVEContainerMatch{
			{Hostname: "gamma", Container: "gitea", Image: "gitea/gitea:1.21", ID: "CVE-2024-6387", Package: "openssh", InstalledVersion: "9.6_p1-r0"},
		},
		AccessibleHosts: 5, Scanned: 4, Unscanned: []string{"delta"}, OldestScan: &old,
	}
	r := cveResult("", e)
	r.Fix["alpha\x00openssh-server"] = "Update"
	ans := cveExposureAnswer(r, time.UTC)
	for _, want := range []string{
		"Yes — 3 hosts are affected by CVE-2024-6387",
		"- alpha: package openssh-server 1:9.2p1-2 (fixed in 1:9.2p1-2+deb12u3), high — fix: Update",
		"- beta: package openssh-server 1:9.2p1-2 (won't fix), high",
		"- gamma: container gitea (gitea/gitea:1.21): openssh 9.6_p1-r0",
		"Based on the latest scan of 4 of 5 hosts (oldest from Nov 1, 2026).",
		"1 host(s) has never been scanned and could still be affected: delta.",
	} {
		if !strings.Contains(ans, want) {
			t.Errorf("answer missing %q:\n%s", want, ans)
		}
	}
}

// "Not found" is only "not vulnerable" for the hosts that were scanned; the answer
// must name the ones that were not rather than read as an all-clear.
func TestCVEAnswerNoneFoundStillNamesUnscannedHosts(t *testing.T) {
	e := &store.CVEExposure{AccessibleHosts: 3, Scanned: 2, Unscanned: []string{"win01"}}
	ans := cveExposureAnswer(cveResult("", e), time.UTC)
	if !strings.HasPrefix(ans, "No — none of the 2 scanned hosts report CVE-2024-6387") {
		t.Errorf("got %q", ans)
	}
	if !strings.Contains(ans, "could still be affected: win01") {
		t.Errorf("unscanned host not named: %q", ans)
	}
	e = &store.CVEExposure{AccessibleHosts: 3, Unscanned: []string{"a", "b", "c"}}
	if ans := cveExposureAnswer(cveResult("", e), time.UTC); !strings.HasPrefix(ans, "Unknown — no host has a completed vulnerability scan") {
		t.Errorf("no scans at all must be Unknown, got %q", ans)
	}
}

func TestCVEAnswerForOneHost(t *testing.T) {
	e := &store.CVEExposure{
		Hosts:           []store.CVEHostMatch{{Hostname: "web01", ID: "CVE-2024-6387", Package: "openssh-server", InstalledVersion: "1:9.2p1-2"}, {Hostname: "web02", ID: "CVE-2024-6387", Package: "openssh-server"}},
		AccessibleHosts: 3, Scanned: 2, Unscanned: []string{"db01"},
	}
	r := cveResult("web01", e)
	narrowToHost(r)
	ans := cveExposureAnswer(r, time.UTC)
	if !strings.HasPrefix(ans, "Yes — web01 is affected by CVE-2024-6387:") || strings.Contains(ans, "web02") {
		t.Errorf("got %q", ans)
	}

	e = &store.CVEExposure{Hosts: []store.CVEHostMatch{{Hostname: "web02", ID: "CVE-2024-6387"}}, AccessibleHosts: 3, Scanned: 2, Unscanned: []string{"db01"}}
	r = cveResult("db01", e)
	narrowToHost(r)
	if ans := cveExposureAnswer(r, time.UTC); !strings.HasPrefix(ans, "Unknown — db01 has no completed vulnerability scan") {
		t.Errorf("unscanned host must be Unknown, got %q", ans)
	}

	e = &store.CVEExposure{Hosts: []store.CVEHostMatch{{Hostname: "web02", ID: "CVE-2024-6387"}}, AccessibleHosts: 3, Scanned: 2}
	r = cveResult("web01", e)
	narrowToHost(r)
	if ans := cveExposureAnswer(r, time.UTC); !strings.HasPrefix(ans, "No — web01's latest vulnerability scan does not report CVE-2024-6387") {
		t.Errorf("got %q", ans)
	}
}

// A GHSA-keyed finding matched through its CVE alias must say which ID it carries,
// or the operator searching their scanner UI for the CVE will not find the row.
func TestCVEAnswerNamesTheStoredIDWhenMatchedByAlias(t *testing.T) {
	e := &store.CVEExposure{
		Hosts:           []store.CVEHostMatch{{Hostname: "ci", ID: "GHSA-49gw-vxvf-fc2g", Package: "stdlib", InstalledVersion: "go1.22.1"}},
		AccessibleHosts: 1, Scanned: 1,
	}
	r := &cveExposureResult{IDs: []string{"CVE-2024-24790"}, Exp: e, Fix: map[string]string{}}
	if ans := cveExposureAnswer(r, time.UTC); !strings.Contains(ans, "[GHSA-49gw-vxvf-fc2g]") {
		t.Errorf("alias match does not name the stored ID: %q", ans)
	}
}
