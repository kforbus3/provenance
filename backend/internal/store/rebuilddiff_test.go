package store

import (
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/models"
)

func pkgs(kv ...string) []ImagePackage {
	var out []ImagePackage
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, ImagePackage{Name: kv[i], Version: kv[i+1], Type: "apk"})
	}
	return out
}

// nginx:alpine, 2026-09-22: rebuilt, and the same packages at the same versions.
// The page said "rebuilt" exactly as it would for a security fix.
func TestARebuildThatChangedNothingSaysSo(t *testing.T) {
	same := pkgs("nginx", "1.31.6-r0", "libssl3", "3.5.8-r0", "busybox", "1.37.0-r31")
	f := []models.VulnFinding{{CVE: "CVE-2026-1", Package: "busybox", Severity: "Medium"}}
	d := DiffRebuild(
		ContainerImageScan{Digest: "old", Packages: same, Findings: f},
		ContainerImageScan{Digest: "new", Packages: same, Findings: f}, true, true)
	if !d.Ready || !d.NoChange() {
		t.Fatalf("an identical rebuild must read as no change: %+v", d)
	}
}

// The case rebuilds exist for: a base-image fix with no new version of its own.
func TestARebuildThatPatchedAPackageNamesItAndCountsTheFixes(t *testing.T) {
	d := DiffRebuild(
		ContainerImageScan{Digest: "old", High: 2, Packages: pkgs("nginx", "1.31.6-r0", "libssl3", "3.5.8-r0", "curl", "8.1"),
			Findings: []models.VulnFinding{
				{CVE: "CVE-2026-10", Package: "libssl3", Severity: "High"},
				{CVE: "CVE-2026-11", Package: "libssl3", Severity: "High"},
			}},
		ContainerImageScan{Digest: "new", Packages: pkgs("nginx", "1.31.6-r0", "libssl3", "3.5.9-r0", "zlib", "1.3")},
		true, true)
	if d.NoChange() {
		t.Fatal("a patched package is a change")
	}
	if len(d.Changed) != 1 || d.Changed[0].Name != "libssl3" || d.Changed[0].From != "3.5.8-r0" || d.Changed[0].To != "3.5.9-r0" {
		t.Fatalf("changed = %+v", d.Changed)
	}
	if len(d.Added) != 1 || d.Added[0].Name != "zlib" || len(d.Removed) != 1 || d.Removed[0].Name != "curl" {
		t.Fatalf("added=%+v removed=%+v", d.Added, d.Removed)
	}
	if d.Fixed != 2 || d.Introduced != 0 || d.Before.High != 2 || d.After.High != 0 {
		t.Fatalf("fixed=%d introduced=%d before=%+v after=%+v", d.Fixed, d.Introduced, d.Before, d.After)
	}
}

// An unscanned or failed build is "cannot compare yet", never an empty difference,
// which would read as "nothing changed".
func TestAnIncompleteComparisonIsNotReportedAsNoChange(t *testing.T) {
	p := pkgs("nginx", "1")
	for name, c := range map[string]struct {
		from, to         ContainerImageScan
		haveFrom, haveTo bool
		want             string
	}{
		"running build never scanned":  {ContainerImageScan{}, ContainerImageScan{Packages: p}, false, true, "these hosts run has not been scanned"},
		"scanned before packages kept": {ContainerImageScan{}, ContainerImageScan{Packages: p}, true, true, "these hosts run has not been scanned"},
		"new build never scanned":      {ContainerImageScan{Packages: p}, ContainerImageScan{}, true, false, "new build has not been scanned"},
		"new build failed":             {ContainerImageScan{Packages: p}, ContainerImageScan{Error: "rate limited"}, true, true, "rate limited"},
	} {
		d := DiffRebuild(c.from, c.to, c.haveFrom, c.haveTo)
		if d.Ready || d.NoChange() || !strings.Contains(d.Reason, c.want) {
			t.Errorf("%s: ready=%v nochange=%v reason=%q", name, d.Ready, d.NoChange(), d.Reason)
		}
	}
}

func TestTheComparisonUsesTheOldBuildMostHostsRun(t *testing.T) {
	from, others := mostCommonStale([]ImageUpdateHost{
		{Digest: "a", Stale: true}, {Digest: "b", Stale: true}, {Digest: "b", Stale: true},
		{Digest: "new", Stale: false}, {Digest: "", Stale: true},
	})
	if from != "b" || others != 1 {
		t.Fatalf("from=%q others=%d", from, others)
	}
}
