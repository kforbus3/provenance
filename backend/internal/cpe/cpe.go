// Package cpe maps Windows application names (registry DisplayName) to CPE
// (Common Platform Enumeration) vendor/product identifiers, so installed
// third-party software can be matched against NVD CVEs by grype. The dictionary is
// intentionally CURATED and precision-first: a small set of high-value, common apps
// with confident CPE identifiers, extended over time. Apps not in the dictionary are
// reported as "not scanned" rather than guessed at (a wrong CPE would produce
// misleading findings). CPE strings here are best-effort and may need tuning.
package cpe

import (
	"fmt"
	"strings"
)

type entry struct {
	match   string // lowercase substring matched against the DisplayName
	vendor  string
	product string
}

// dictionary is ordered most-specific first (first match wins). Microsoft products
// serviced by Windows Update (.NET, Office, Edge legacy) are deliberately omitted —
// those are covered by the MSRC path, and duplicating them here would double-count.
var dictionary = []entry{
	{"google chrome", "google", "chrome"},
	{"mozilla firefox", "mozilla", "firefox"},
	{"mozilla thunderbird", "mozilla", "thunderbird"},
	{"vlc media player", "videolan", "vlc_media_player"},
	{"7-zip", "7-zip", "7-zip"},
	{"notepad++", "notepad-plus-plus", "notepad\\+\\+"},
	{"wireshark", "wireshark", "wireshark"},
	{"openvpn", "openvpn", "openvpn"},
	{"winscp", "winscp", "winscp"},
	{"filezilla", "filezilla", "filezilla"},
	{"openssl", "openssl", "openssl"},
	{"node.js", "nodejs", "node.js"},
	{"adobe acrobat reader", "adobe", "acrobat_reader_dc"},
	{"libreoffice", "libreoffice", "libreoffice"},
	{"visual studio code", "microsoft", "visual_studio_code"},
	{"docker desktop", "docker", "docker_desktop"},
	{"postgresql", "postgresql", "postgresql"},
	{"putty", "putty", "putty"},
	// "python 3" (not bare "python", which also matches launchers/libraries).
	{"python 3", "python", "python"},

	// --- Additional curated entries (v0.36.x). Same precision-first rule: only
	// apps whose NVD vendor/product is confidently known. Multi-word matches are
	// used where a bare token would over-match (e.g. "mysql server" so MySQL
	// Workbench doesn't map to the server's CVEs; "keepassxc" before "keepass" so
	// the distinct products don't collide — most-specific first, first match wins).
	{"winrar", "rarlab", "winrar"},
	{"teamviewer", "teamviewer", "teamviewer"},
	{"slack", "slack", "slack"},
	{"oracle vm virtualbox", "oracle", "vm_virtualbox"},
	{"vmware workstation", "vmware", "workstation"},
	{"gimp", "gimp", "gimp"},
	{"audacity", "audacityteam", "audacity"},
	{"keepassxc", "keepassxc", "keepassxc"},
	{"keepass", "keepass", "keepass"},
	{"dropbox", "dropbox", "dropbox"},
	{"opera", "opera", "opera"},
	{"apache tomcat", "apache", "tomcat"},
	{"apache http server", "apache", "http_server"},
	{"mysql server", "oracle", "mysql"},
	{"nginx", "nginx", "nginx"},
	{"grafana", "grafana", "grafana"},
	{"jenkins", "jenkins", "jenkins"},
}

// Match returns the CPE vendor/product for an app DisplayName, if it is in the
// curated dictionary.
func Match(name string) (vendor, product string, ok bool) {
	l := strings.ToLower(name)
	for _, e := range dictionary {
		if strings.Contains(l, e.match) {
			return e.vendor, e.product, true
		}
	}
	return "", "", false
}

// CPE builds a CPE 2.3 application string for a mapped app + version. Returns "" if
// there is no usable version (a version-less CPE would match every version's CVEs).
func CPE(vendor, product, version string) string {
	v := NormalizeVersion(version)
	if v == "" {
		return ""
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, v)
}

// NormalizeVersion reduces a registry DisplayVersion to a CPE-friendly version: the
// leading dotted-numeric token (e.g. "120.0.6099.109 (x64)" → "120.0.6099.109").
func NormalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(strings.ToLower(v), "v")
	// Take the leading run of digits and dots.
	end := 0
	for end < len(v) {
		c := v[end]
		if (c >= '0' && c <= '9') || c == '.' {
			end++
			continue
		}
		break
	}
	out := strings.Trim(v[:end], ".")
	// Require at least one digit.
	if !strings.ContainsAny(out, "0123456789") {
		return ""
	}
	return out
}
