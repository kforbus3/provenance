package assistant

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// ---------------------------------------------------------------------------
// vulnerabilities{cve} — "which hosts are vulnerable to CVE-X"
// ---------------------------------------------------------------------------
//
// Without this the question had nowhere to go: the fast path sent every CVE
// question to the fleet roll-up, which is per-host COUNTS, the ID was thrown
// away, and the model — correctly — said it had no information about that CVE.
// The lookup runs across each host's latest package scan (including Windows
// MSRC findings, which land in the same table), the scans of every container
// image those hosts are running, and the latest network scans. The answer is
// built in code: listing the affected hosts is an enumeration, and a small model
// truncates enumerations.

// vulnIDRE matches a CVE or a GitHub advisory ID anywhere in free text.
var vulnIDRE = regexp.MustCompile(`(?i)\b(?:cve-\d{4}-\d{4,}|ghsa(?:-[0-9a-z]{4}){3})\b`)

// vulnIDsFromText returns the distinct CVE/GHSA IDs in s, upper-cased, in the
// order they appear.
func vulnIDsFromText(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range vulnIDRE.FindAllString(s, -1) {
		id := strings.ToUpper(m)
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// cveExposureResult is the lookup plus everything the answer needs, kept apart from
// the store so the answer can be tested without a database.
type cveExposureResult struct {
	IDs  []string
	Host string // empty = fleet-wide
	// HostUnscanned: the one host asked about has no completed package scan.
	HostUnscanned bool
	Exp           *store.CVEExposure
	// Fix is the per-host-package remediation label ("Update", "Remove (orphaned)",
	// "No apt fix"), keyed by hostname+"\x00"+package.
	Fix map[string]string
}

func (s *Service) runCVEExposure(ctx context.Context, a vulnArgs, who Caller) (*AssistantTable, any, string) {
	ids := vulnIDsFromText(a.CVE)
	if len(ids) == 0 {
		return nil, map[string]any{"error": fmt.Sprintf("%q is not a CVE or GHSA identifier (expected e.g. CVE-2024-6387)", a.CVE)}, ""
	}
	hostname := strings.ToLower(strings.TrimSpace(a.Hostname))
	if hostname != "" {
		host, err := s.store.HostByHostname(ctx, hostname)
		if err != nil {
			return nil, map[string]any{"error": "no host named " + hostname}, ""
		}
		if !who.IsSuperAdmin {
			ok, aerr := s.store.UserCanAccessHost(ctx, who.UserID, host.ID)
			if aerr != nil || !ok {
				return nil, map[string]any{"error": "you do not have access to that host"}, ""
			}
		}
		hostname = host.Hostname
	}
	exp, err := s.store.CVEExposureForAssistant(ctx, who.UserID, who.IsSuperAdmin, ids)
	if err != nil {
		s.log.Warn("assistant cve exposure", "err", err)
		return nil, map[string]any{"error": "could not read vulnerability scans"}, ""
	}
	r := &cveExposureResult{IDs: ids, Host: hostname, Exp: exp, Fix: map[string]string{}}
	if hostname != "" {
		narrowToHost(r)
	}
	s.classifyCVEFixes(ctx, r)

	tbl := cveExposureTable(r)
	answer := cveExposureAnswer(r, s.displayLoc(ctx))
	payload := map[string]any{
		"ids": ids, "host": hostname,
		"affectedHosts": affectedHosts(r),
		"packages":      exp.Hosts, "containers": exp.Containers, "network": exp.Network,
		"accessibleHosts": exp.AccessibleHosts, "scannedHosts": exp.Scanned, "unscannedHosts": exp.Unscanned,
		"answer": answer,
	}
	return tbl, payload, answer
}

// narrowToHost keeps only the matches on r.Host and reduces the coverage to it.
func narrowToHost(r *cveExposureResult) {
	e := r.Exp
	hosts := e.Hosts[:0:0]
	for _, m := range e.Hosts {
		if strings.EqualFold(m.Hostname, r.Host) {
			hosts = append(hosts, m)
		}
	}
	ctrs := e.Containers[:0:0]
	for _, m := range e.Containers {
		if strings.EqualFold(m.Hostname, r.Host) {
			ctrs = append(ctrs, m)
		}
	}
	net := e.Network[:0:0]
	for _, m := range e.Network {
		if strings.EqualFold(m.Hostname, r.Host) {
			net = append(net, m)
		}
	}
	for _, u := range e.Unscanned {
		if strings.EqualFold(u, r.Host) {
			r.HostUnscanned = true
		}
	}
	e.Hosts, e.Containers, e.Network = hosts, ctrs, net
}

// classifyCVEFixes labels each host-package match with HOW to fix it on that
// host, the same classification the per-host findings table uses.
func (s *Service) classifyCVEFixes(ctx context.Context, r *cveExposureResult) {
	byHost := map[string]*models.Host{}
	for _, m := range r.Exp.Hosts {
		h, seen := byHost[m.Hostname]
		if !seen {
			h, _ = s.store.HostByHostname(ctx, m.Hostname)
			byHost[m.Hostname] = h
		}
		if h == nil || h.Inventory == nil {
			continue
		}
		obsolete, pending := map[string]bool{}, map[string]bool{}
		for _, p := range h.Inventory.ObsoletePackages {
			obsolete[p] = true
		}
		for _, u := range h.Inventory.UpdatePackages {
			pending[u.Package] = true
		}
		f := models.VulnFinding{CVE: m.ID, Package: m.Package, InstalledVersion: m.InstalledVersion,
			FixedVersion: m.FixedVersion, FixState: m.FixState}
		r.Fix[m.Hostname+"\x00"+m.Package] = remediationLabel(
			models.ClassifyRemediation(f, obsolete, pending, h.Inventory.UpdatesCheckedAt != nil))
	}
}

// affectedHosts is the distinct hostnames with any match, sorted.
func affectedHosts(r *cveExposureResult) []string {
	set := map[string]bool{}
	for _, m := range r.Exp.Hosts {
		set[m.Hostname] = true
	}
	for _, m := range r.Exp.Containers {
		set[m.Hostname] = true
	}
	for _, m := range r.Exp.Network {
		set[m.Hostname] = true
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func cveExposureTable(r *cveExposureResult) *AssistantTable {
	e := r.Exp
	if len(e.Hosts)+len(e.Containers)+len(e.Network) == 0 {
		return nil
	}
	title := "Hosts affected by " + strings.Join(r.IDs, ", ")
	if r.Host != "" {
		title = strings.Join(r.IDs, ", ") + " on " + r.Host
	}
	tbl := &AssistantTable{
		Title: title,
		Columns: []TableColumn{{Label: "Host"}, {Label: "Where"}, {Label: "ID"}, {Label: "Package"},
			{Label: "Installed"}, {Label: "Fixed in"}, {Label: "Severity"}, {Label: "CVSS"}, {Label: "Fix"}},
	}
	for _, m := range e.Hosts {
		tbl.Rows = append(tbl.Rows, []string{m.Hostname, "host package", m.ID, m.Package, m.InstalledVersion,
			fixedText(m.FixedVersion, m.FixState), m.Severity, fmt.Sprintf("%.1f", m.CVSSScore), r.Fix[m.Hostname+"\x00"+m.Package]})
	}
	for _, m := range e.Containers {
		tbl.Rows = append(tbl.Rows, []string{m.Hostname, "container " + m.Container + " (" + m.Image + ")", m.ID, m.Package,
			m.InstalledVersion, m.FixedVersion, m.Severity, fmt.Sprintf("%.1f", m.CVSSScore), "Rebuild/update image"})
	}
	for _, m := range e.Network {
		tbl.Rows = append(tbl.Rows, []string{m.Hostname, fmt.Sprintf("network %d/%s (%s)", m.Port, m.Proto, m.Path),
			strings.Join(r.IDs, ", "), m.Name, "", "", m.Severity, "", ""})
	}
	return tbl
}

// fixedText renders "fixed in" for a finding, keeping the tracker's verdict when
// there is no version: "won't fix" and "not fixed yet" are different answers.
func fixedText(version, state string) string {
	if version != "" {
		return version
	}
	switch state {
	case models.FixStateWontFix:
		return "won't fix"
	case models.FixStateNotFixed:
		return "no fix yet"
	}
	return ""
}

// cveExposureAnswer is the deterministic answer to "which hosts are vulnerable to
// <ids>" (or "is <host> vulnerable to <ids>"). It always says what the answer is
// based on, because "not found" over three scanned hosts out of fourteen is not
// "not vulnerable".
func cveExposureAnswer(r *cveExposureResult, loc *time.Location) string {
	e := r.Exp
	ids := strings.Join(r.IDs, ", ")
	var b strings.Builder

	type where struct{ lines []string }
	per := map[string]*where{}
	add := func(h, line string) {
		w := per[h]
		if w == nil {
			w = &where{}
			per[h] = w
		}
		for _, l := range w.lines {
			if l == line {
				return
			}
		}
		w.lines = append(w.lines, line)
	}
	for _, m := range e.Hosts {
		line := fmt.Sprintf("package %s %s", m.Package, m.InstalledVersion)
		if ft := fixedText(m.FixedVersion, m.FixState); ft != "" {
			if m.FixedVersion != "" {
				line += " (fixed in " + ft + ")"
			} else {
				line += " (" + ft + ")"
			}
		}
		if sev := strings.TrimSpace(m.Severity); sev != "" {
			line += ", " + strings.ToLower(sev)
		}
		if fix := r.Fix[m.Hostname+"\x00"+m.Package]; fix != "" {
			line += " — fix: " + fix
		}
		if len(r.IDs) > 1 || !strings.EqualFold(m.ID, r.IDs[0]) {
			line += " [" + m.ID + "]"
		}
		add(m.Hostname, line)
	}
	for _, m := range e.Containers {
		line := fmt.Sprintf("container %s (%s): %s %s", m.Container, m.Image, m.Package, m.InstalledVersion)
		if m.FixedVersion != "" {
			line += " (fixed in " + m.FixedVersion + ")"
		}
		add(m.Hostname, line)
	}
	for _, m := range e.Network {
		add(m.Hostname, fmt.Sprintf("network check \"%s\" on %d/%s via %s", m.Name, m.Port, m.Proto, m.Path))
	}
	hosts := affectedHosts(r)

	if r.Host != "" {
		switch {
		case len(hosts) > 0:
			fmt.Fprintf(&b, "Yes — %s is affected by %s:\n", r.Host, ids)
			for _, l := range per[r.Host].lines {
				b.WriteString("- " + l + "\n")
			}
		case r.HostUnscanned:
			fmt.Fprintf(&b, "Unknown — %s has no completed vulnerability scan, so Provenance cannot say whether it is affected by %s. Run a vulnerability scan of %s to find out.", r.Host, ids, r.Host)
			return b.String()
		default:
			fmt.Fprintf(&b, "No — %s's latest vulnerability scan does not report %s (host packages, running container images and network checks were all checked).", r.Host, ids)
		}
		return strings.TrimRight(b.String(), "\n")
	}

	if len(hosts) > 0 {
		noun := "hosts are"
		if len(hosts) == 1 {
			noun = "host is"
		}
		fmt.Fprintf(&b, "Yes — %d %s affected by %s:\n", len(hosts), noun, ids)
		for _, h := range hosts {
			lines := per[h].lines
			if len(lines) == 1 {
				fmt.Fprintf(&b, "- %s: %s\n", h, lines[0])
				continue
			}
			fmt.Fprintf(&b, "- %s:\n", h)
			for _, l := range lines {
				b.WriteString("  - " + l + "\n")
			}
		}
	} else if e.Scanned > 0 {
		fmt.Fprintf(&b, "No — none of the %d scanned hosts report %s (host packages, running container images and network checks).", e.Scanned, ids)
	} else {
		fmt.Fprintf(&b, "Unknown — no host has a completed vulnerability scan, so Provenance cannot say whether any host is affected by %s.", ids)
		return b.String()
	}

	var notes []string
	if e.Scanned > 0 {
		basis := fmt.Sprintf("Based on the latest scan of %d of %d hosts", e.Scanned, e.AccessibleHosts)
		if e.OldestScan != nil {
			basis += fmt.Sprintf(" (oldest from %s)", e.OldestScan.In(loc).Format("Jan 2, 2006"))
		}
		notes = append(notes, basis+".")
	}
	if n := len(e.Unscanned); n > 0 {
		names := e.Unscanned
		more := ""
		if n > 10 {
			names, more = names[:10], fmt.Sprintf(" and %d more", n-10)
		}
		verb := "have"
		if n == 1 {
			verb = "has"
		}
		notes = append(notes, fmt.Sprintf("%d host(s) %s never been scanned and could still be affected: %s%s.", n, verb, strings.Join(names, ", "), more))
	}
	if len(notes) > 0 {
		sep := " " // after the one-line "No —" sentence
		if len(hosts) > 0 {
			sep = "" // the host list already ends in a newline
		}
		b.WriteString(sep + strings.Join(notes, " "))
	}
	return strings.TrimSpace(b.String())
}
