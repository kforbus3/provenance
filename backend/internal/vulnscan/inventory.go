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
fi

# Software the package manager does not know about.
#
# Everything above reads dpkg or rpm, so it sees only what the distribution
# installed. A pip install, an npm install, a vendored application dependency --
# none of it appears, and those are exactly where the interesting vulnerabilities
# tend to live. A host can be reported clean while serving a Django with a
# published RCE, because Django came from pip.
#
# Bounded deliberately. This runs on every scanned host over SSH and must not
# turn into a filesystem walk: the search is limited to the directories these
# ecosystems actually install into, to a shallow depth, and to a fixed number of
# results. Missing a package is a worse report; hanging the scan is a worse
# product.
PY_DIRS="/usr/lib/python3*/dist-packages /usr/lib/python3*/site-packages /usr/local/lib/python3*/*-packages /opt/*/lib/python3*/*-packages"
for d in $PY_DIRS; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 1 -name '*.dist-info' -o -maxdepth 1 -name '*.egg-info' 2>/dev/null
done | head -2000 | while read -r meta; do
  base=$(basename "$meta")
  # "requests-2.28.1.dist-info" -> name, version. Splitting on the LAST hyphen
  # before the version, because package names contain hyphens too.
  stem=${base%.dist-info}; stem=${stem%.egg-info}
  ver=${stem##*-}; nm=${stem%-*}
  case "$ver" in ''|*[!0-9.]*[!0-9.a-zA-Z]*) continue;; esac
  [ -n "$nm" ] && [ -n "$ver" ] && printf '#pypi\t%s\t%s\n' "$nm" "$ver"
done

NODE_DIRS="/usr/lib/node_modules /usr/local/lib/node_modules /opt/*/node_modules /srv/*/node_modules"
for d in $NODE_DIRS; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 2 -name package.json 2>/dev/null
done | head -2000 | while read -r pj; do
  nm=$(sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$pj" 2>/dev/null | head -1)
  ver=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$pj" 2>/dev/null | head -1)
  [ -n "$nm" ] && [ -n "$ver" ] && printf '#npm\t%s\t%s\n' "$nm" "$ver"
done`

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
	// Ecosystem packages found outside the distribution's package manager --
	// pip and npm installs. Kept separate from Packages because their purl is a
	// different shape: they have no distro namespace and no architecture, and
	// forcing them through the deb/rpm purl builder produces identifiers grype
	// will never match.
	Ecosystem []ecoPackage
}

// ecoPackage is one language-ecosystem package: the kind dpkg and rpm cannot see.
type ecoPackage struct {
	Kind    string // pypi | npm
	Name    string
	Version string
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
			case (f[0] == "#pypi" || f[0] == "#npm") && len(f) >= 3:
				if f[1] != "" && f[2] != "" {
					inv.Ecosystem = append(inv.Ecosystem, ecoPackage{
						Kind: strings.TrimPrefix(f[0], "#"), Name: f[1], Version: f[2],
					})
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

// ecoPurl builds the package URL for an ecosystem package.
//
// No distro namespace and no architecture, unlike the deb/rpm form: a pypi
// package is the same artifact whichever distribution it was installed on, and
// grype keys its pypi and npm matchers on exactly this shape. Putting a distro
// namespace on it produces an identifier that matches nothing, which looks the
// same as a clean host.
func ecoPurl(e ecoPackage) string {
	if e.Kind == "" || e.Name == "" || e.Version == "" {
		return ""
	}
	// npm scoped packages are "@scope/name" and their purl keeps the scope as a
	// namespace: pkg:npm/%40scope/name@1.0.0.
	name := e.Name
	if e.Kind == "npm" && strings.HasPrefix(name, "@") {
		if i := strings.Index(name, "/"); i > 0 {
			// The scope becomes the purl namespace, and its leading "@" is
			// percent-encoded: an unescaped one would be read as the separator
			// that introduces the version, which is the LAST "@" in a purl.
			// pkg:npm/@angular/core@15.2.0 is ambiguous; %40angular is not.
			return "pkg:npm/%40" + purlEscape(strings.TrimPrefix(name[:i], "@")) +
				"/" + purlEscape(name[i+1:]) + "@" + purlEscape(e.Version)
		}
	}
	if e.Kind == "pypi" {
		// PEP 503 normalisation, because the two ends spell it differently.
		//
		// A dist-info directory is named with the ESCAPED project name --
		// python_dateutil-2.9.0.dist-info -- while advisories, and therefore
		// grype's matcher, use the normalised one: lowercase, with any run of
		// dots, hyphens and underscores collapsed to a single hyphen. Emitting
		// pkg:pypi/python_dateutil@2.9.0 matches nothing at all, and a package
		// that matches nothing is indistinguishable from a package with no
		// vulnerabilities.
		name = normalizePyPIName(name)
	}
	return "pkg:" + e.Kind + "/" + purlEscape(name) + "@" + purlEscape(e.Version)
}

// normalizePyPIName applies PEP 503: lowercase, and every run of ".-_" becomes a
// single hyphen.
func normalizePyPIName(s string) string {
	var b strings.Builder
	prevSep := false
	for _, r := range strings.ToLower(s) {
		if r == '.' || r == '-' || r == '_' {
			if !prevSep {
				b.WriteByte('-')
				prevSep = true
			}
			continue
		}
		b.WriteRune(r)
		prevSep = false
	}
	return strings.Trim(b.String(), "-")
}
