package store

import (
	"sort"
	"strings"
)

// RebuildDiff is what a rebuilt image changed: the build hosts run against the one
// the tag points at now.
//
// A tag republished under the same version shows on the Updates page as "rebuilt",
// which says the bytes differ and nothing about how. Most rebuilds carry base-image
// security fixes that never get a version number of their own; some change nothing
// installed at all (nginx:alpine on 2026-09-22: the same 71 packages at the same
// versions). The two look identical without this, so either every rebuild is urgent
// or none is.
type RebuildDiff struct {
	// Ready is false until both builds have been scanned with package lists.
	// Reason then says which one is missing, or why a scan failed.
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`

	FromDigest string `json:"fromDigest"`
	ToDigest   string `json:"toDigest"`
	// OtherRunning counts further old builds some hosts run, beyond FromDigest, the
	// one most hosts run. Their changes may differ.
	OtherRunning int `json:"otherRunning,omitempty"`

	Changed []PackageChange `json:"changed"`
	Added   []ImagePackage  `json:"added"`
	Removed []ImagePackage  `json:"removed"`

	Before VulnTally `json:"before"`
	After  VulnTally `json:"after"`
	// Fixed and Introduced count vulnerability findings (a CVE in a package) present
	// in one build and not the other.
	Fixed      int `json:"fixed"`
	Introduced int `json:"introduced"`
	// DBDiffers is true when the two scans used different vulnerability databases,
	// so part of the difference in findings may be the data rather than the image.
	DBDiffers bool `json:"dbDiffers,omitempty"`
}

// PackageChange is a package present in both builds at different versions.
type PackageChange struct {
	Name string `json:"name"`
	Type string `json:"type"`
	From string `json:"from"`
	To   string `json:"to"`
}

// VulnTally counts one build's findings.
type VulnTally struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Total    int `json:"total"`
}

// DiffRebuild compares the scan of the running build with the scan of the new one.
// Either may be missing or incomplete; the result then says so rather than
// reporting an empty difference, which would read as "nothing changed".
func DiffRebuild(from, to ContainerImageScan, haveFrom, haveTo bool) RebuildDiff {
	d := RebuildDiff{FromDigest: from.Digest, ToDigest: to.Digest,
		Changed: []PackageChange{}, Added: []ImagePackage{}, Removed: []ImagePackage{}}
	switch {
	case !haveFrom || (from.Error == "" && from.Packages == nil):
		d.Reason = "the build these hosts run has not been scanned for its packages yet"
		return d
	case from.Error != "":
		d.Reason = "the build these hosts run could not be scanned: " + from.Error
		return d
	case !haveTo || (to.Error == "" && to.Packages == nil):
		d.Reason = "the new build has not been scanned for its packages yet"
		return d
	case to.Error != "":
		d.Reason = "the new build could not be scanned: " + to.Error
		return d
	}
	d.Ready = true

	key := func(p ImagePackage) string { return p.Type + "\x00" + p.Name }
	old := map[string]ImagePackage{}
	for _, p := range from.Packages {
		old[key(p)] = p
	}
	now := map[string]ImagePackage{}
	for _, p := range to.Packages {
		now[key(p)] = p
	}
	for k, p := range now {
		if o, ok := old[k]; !ok {
			d.Added = append(d.Added, p)
		} else if o.Version != p.Version {
			d.Changed = append(d.Changed, PackageChange{Name: p.Name, Type: p.Type, From: o.Version, To: p.Version})
		}
	}
	for k, p := range old {
		if _, ok := now[k]; !ok {
			d.Removed = append(d.Removed, p)
		}
	}
	sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].Name < d.Changed[j].Name })
	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].Name < d.Added[j].Name })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].Name < d.Removed[j].Name })

	d.Before, d.After = tally(from), tally(to)
	finding := func(cve, pkg string) string { return cve + "\x00" + pkg }
	before, after := map[string]bool{}, map[string]bool{}
	for _, f := range from.Findings {
		before[finding(f.CVE, f.Package)] = true
	}
	for _, f := range to.Findings {
		after[finding(f.CVE, f.Package)] = true
	}
	for k := range before {
		if !after[k] {
			d.Fixed++
		}
	}
	for k := range after {
		if !before[k] {
			d.Introduced++
		}
	}
	d.DBDiffers = from.DBBuilt != "" && to.DBBuilt != "" && from.DBBuilt != to.DBBuilt
	return d
}

func tally(s ContainerImageScan) VulnTally {
	t := VulnTally{Critical: s.Critical, High: s.High, Total: len(s.Findings)}
	if t.Total == 0 {
		t.Total = s.Critical + s.High + s.Medium + s.Low
	}
	return t
}

// NoChange reports a rebuild that changed no installed package and no finding.
func (d RebuildDiff) NoChange() bool {
	return d.Ready && len(d.Changed) == 0 && len(d.Added) == 0 && len(d.Removed) == 0 &&
		d.Fixed == 0 && d.Introduced == 0
}

// mostCommonStale is the old build most hosts run under a rebuilt tag, and how many
// other old builds there are.
func mostCommonStale(hosts []ImageUpdateHost) (string, int) {
	count := map[string]int{}
	for _, h := range hosts {
		if h.Stale && h.Digest != "" {
			count[h.Digest]++
		}
	}
	best, n := "", 0
	for dg, c := range count {
		if c > n || (c == n && strings.Compare(dg, best) < 0) {
			best, n = dg, c
		}
	}
	if best == "" {
		return "", 0
	}
	return best, len(count) - 1
}
