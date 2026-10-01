package netscan

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// Correlation between the two halves of vulnerability scanning.
//
// grype reports thousands of CVEs on a typical Linux host, and almost none say
// anything about whether an attacker can reach them. The network scan knows what is
// reachable but, from outside, only sees version banners -- which on a distribution
// that backports fixes is routinely wrong. Each fixes the other's blind spot:
//
//   - A grype finding whose package owns, or is loaded by, a process listening on a
//     port the network scan reached is EXPOSED. That is the short list.
//   - A network finding whose CVE the package scan also reports is CONFIRMED. One
//     the package scan -- which knows the real, possibly patched, version -- does not
//     report is BANNER-ONLY, and most likely a false positive.

// exposureIndex is what one host's latest network scans say about its packages.
type exposureIndex struct {
	byPackage map[string]*models.NetExposure
	netCVEs   map[string]models.NetFinding
}

// buildExposureIndex reads the host's latest scan on each path.
func buildExposureIndex(scans []models.NetScan) *exposureIndex {
	idx := &exposureIndex{byPackage: map[string]*models.NetExposure{}, netCVEs: map[string]models.NetFinding{}}
	for _, sc := range scans {
		if sc.Status != models.NetScanCompleted {
			continue
		}
		for _, f := range sc.Findings {
			for _, c := range f.CVEs {
				c = strings.ToUpper(c)
				if _, ok := idx.netCVEs[c]; !ok {
					idx.netCVEs[c] = f
				}
			}
		}
		if !sc.ListenersKnown {
			continue
		}
		for _, sv := range sc.Services {
			l := listenerFor(sc.Listeners, sv.Proto, sv.Port)
			if l == nil {
				continue
			}
			mark := func(pkg, via string) {
				if pkg == "" {
					return
				}
				e, ok := idx.byPackage[pkg]
				if !ok {
					e = &models.NetExposure{Port: sv.Port, Proto: sv.Proto, Process: l.Process, Via: via}
					idx.byPackage[pkg] = e
				} else if e.Via == "library" && via == "binary" {
					// Owning the listening binary is the stronger statement; lead with it.
					e.Port, e.Proto, e.Process, e.Via = sv.Port, sv.Proto, l.Process, via
				}
				if !contains(e.Paths, sc.Path) {
					e.Paths = append(e.Paths, sc.Path)
					sort.Strings(e.Paths)
				}
				ep := fmt.Sprintf("%d/%s %s (%s)", sv.Port, sv.Proto, l.Process, sc.Path)
				if !contains(e.Endpoints, ep) {
					e.Endpoints = append(e.Endpoints, ep)
				}
			}
			mark(l.Package, "binary")
			for _, lp := range l.LibPackages {
				mark(lp, "library")
			}
		}
	}
	return idx
}

func contains(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}

// annotate sets Exposure on grype findings.
func (idx *exposureIndex) annotate(findings []models.VulnFinding) {
	for i := range findings {
		f := &findings[i]
		var e *models.NetExposure
		for _, pkg := range []string{f.Package, f.SourcePackage} {
			if x, ok := idx.byPackage[pkg]; ok && pkg != "" {
				cp := *x
				cp.Paths = append([]string(nil), x.Paths...)
				cp.Endpoints = append([]string(nil), x.Endpoints...)
				e = &cp
				break
			}
		}
		if nf, ok := idx.netCVEs[strings.ToUpper(f.CVE)]; ok {
			if e == nil {
				e = &models.NetExposure{Port: nf.Port, Proto: nf.Proto, Via: "network"}
			}
			e.Network = true
		}
		f.Exposure = e
	}
}

// corroborate sets Corroboration on network findings against the host's package scan.
func corroborate(findings []models.NetFinding, grypeCVEs map[string]bool, havePackageScan bool) {
	for i := range findings {
		f := &findings[i]
		if len(f.CVEs) == 0 || !havePackageScan {
			continue
		}
		f.Corroboration = "banner-only"
		for _, c := range f.CVEs {
			if grypeCVEs[strings.ToUpper(c)] {
				f.Corroboration = "confirmed"
				break
			}
		}
	}
}

// AnnotateVulnFindings marks a host's grype findings with their network exposure.
// Best-effort: with no network scans, or on any error, findings are left as they were.
func AnnotateVulnFindings(ctx context.Context, st *store.Store, hostID uuid.UUID, findings []models.VulnFinding) {
	scans, err := st.LatestNetScansForHost(ctx, hostID)
	if err != nil || len(scans) == 0 {
		return
	}
	buildExposureIndex(scans).annotate(findings)
}

// CorroborateHostScans marks the network findings in a host's scans against its
// latest package scan.
func CorroborateHostScans(ctx context.Context, st *store.Store, hostID uuid.UUID, scans []models.NetScan) {
	cves, ok, err := st.LatestVulnCVEsForHost(ctx, hostID)
	if err != nil {
		return
	}
	for i := range scans {
		corroborate(scans[i].Findings, cves, ok)
	}
}
