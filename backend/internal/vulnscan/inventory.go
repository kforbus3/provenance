package vulnscan

import (
	"fmt"
	"strings"
)

// Package inventory collection.
//
// The scan already tars a host's package databases and ships them to grype.
// This asks the host a second, simpler question in the same SSH session: what is
// installed, by name, version and architecture.
//
// Querying the package manager rather than parsing the databases we already
// collected is deliberate. /var/lib/dpkg/status is a text file and easy enough,
// but the rpm database is Berkeley DB on older distros and SQLite on newer ones,
// and decoding either in Go to produce an inventory the host itself can print in
// one command would be a lot of code to maintain for no extra fidelity.

// inventoryScript prints a small tab-separated inventory.
//
// The `#os` and `#fmt` header lines carry what the components need but the rows
// do not: the distribution identity, which is part of a purl, and which package
// manager answered. Comment-prefixed so the parser can ignore anything it does
// not recognise and stay compatible with a future field.
//
// No sudo: both queries read world-readable state, and the scan's privileged
// connection is already used for the archive. Keeping this unprivileged means a
// host that has tightened its sudoers still yields an inventory.
const inventoryScript = `set -u
if [ -r /etc/os-release ]; then . /etc/os-release; fi
printf '#os\t%s\t%s\n' "${ID:-unknown}" "${VERSION_ID:-}"
if command -v dpkg-query >/dev/null 2>&1; then
  printf '#fmt\tdeb\n'
  dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n' 2>/dev/null \
    | awk -F'\t' '$4 == "installed" { print $1 "\t" $2 "\t" $3 }'
elif command -v rpm >/dev/null 2>&1; then
  printf '#fmt\trpm\n'
  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n' 2>/dev/null
else
  printf '#fmt\tnone\n'
fi`

// maxInventoryBytes caps the reply. A very large host runs to a few hundred
// kilobytes of plain text; the cap is generous but bounded, because this is
// remote input.
const maxInventoryBytes = 8 << 20

// inventory is a host's installed package set.
type inventory struct {
	OSID      string
	OSVersion string
	// Format is "deb", "rpm" or "" when neither package manager was found.
	Format   string
	Packages []invPackage
}

type invPackage struct {
	Name    string
	Version string
	Arch    string
}

// parseInventory reads the script's output.
//
// Tolerant by design: a malformed row is skipped rather than failing the whole
// inventory, because this runs after a successful vulnerability scan and losing
// the SBOM over one odd line would be a poor trade.
func parseInventory(out string) inventory {
	inv := inventory{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			f := strings.Split(line, "\t")
			switch {
			case f[0] == "#os" && len(f) >= 3:
				inv.OSID, inv.OSVersion = f[1], f[2]
			case f[0] == "#fmt" && len(f) >= 2:
				if f[1] != "none" {
					inv.Format = f[1]
				}
			}
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 3 || f[0] == "" || f[1] == "" {
			continue
		}
		inv.Packages = append(inv.Packages, invPackage{
			Name: f[0], Version: f[1], Arch: f[2],
		})
	}
	return inv
}

// purl builds a package URL for one entry.
//
// purls are used for Linux instead of the CPEs the Windows path relies on
// because distribution package identity is unambiguous — "curl 7.88.1-10 amd64
// from debian" names exactly one artifact, where Windows software names need a
// curated CPE mapping to mean anything. Consumers (grype, Dependency-Track,
// anything reading CycloneDX) match Linux components far more accurately on a
// purl than on a synthesised CPE.
//
// Format: pkg:deb/debian/curl@7.88.1-10?arch=amd64&distro=debian-12
func purl(inv inventory, p invPackage) string {
	kind := inv.Format
	if kind == "" {
		return ""
	}
	namespace := inv.OSID
	if namespace == "" {
		namespace = "unknown"
	}
	// Debian derivatives publish under their own namespace; the purl spec keys
	// deb packages on the distribution that built them.
	s := fmt.Sprintf("pkg:%s/%s/%s@%s", kind, purlEscape(namespace),
		purlEscape(p.Name), purlEscape(p.Version))
	q := []string{}
	if p.Arch != "" {
		q = append(q, "arch="+purlEscape(p.Arch))
	}
	if inv.OSID != "" && inv.OSVersion != "" {
		q = append(q, "distro="+purlEscape(inv.OSID+"-"+inv.OSVersion))
	}
	if len(q) > 0 {
		s += "?" + strings.Join(q, "&")
	}
	return s
}

// purlEscape percent-encodes the characters that are structural in a purl.
//
// Deliberately narrow rather than a full url.QueryEscape: purls keep ':' and '+'
// literal, and those appear in real Debian versions (epochs like `2:1.4` and
// build suffixes like `1.2+deb12u1`). Escaping them would produce identifiers
// that no consumer matches.
func purlEscape(s string) string {
	r := strings.NewReplacer(
		"%", "%25",
		" ", "%20",
		"#", "%23",
		"?", "%3F",
		"&", "%26",
		"/", "%2F",
	)
	return r.Replace(s)
}
