package vulnscan

import (
	"encoding/json"
	"strings"
	"testing"
)

// Software the package manager cannot see.
//
// The SBOM was built purely from dpkg/rpm, so it described only what the
// distribution installed. A pip install, an npm install, a vendored application
// dependency — none of it appeared, and those are where the interesting
// vulnerabilities tend to live. A host could be reported clean while serving a
// Django with a published RCE, because Django came from pip.

func TestEcosystemPackagesAreParsed(t *testing.T) {
	inv := parseInventory(strings.Join([]string{
		"#os\tdebian\t12",
		"#fmt\tdeb",
		"curl\t7.88.1-10\tamd64",
		"#pypi\tDjango\t4.2.1",
		"#npm\tlodash\t4.17.20",
		"#npm\t@angular/core\t15.2.0",
	}, "\n"))

	if len(inv.Packages) != 1 {
		t.Errorf("distribution packages = %d, want 1", len(inv.Packages))
	}
	if len(inv.Ecosystem) != 3 {
		t.Fatalf("ecosystem packages = %d, want 3: %+v", len(inv.Ecosystem), inv.Ecosystem)
	}
}

// grype keys its pypi and npm matchers on this exact shape. A distro namespace
// or an architecture qualifier — the deb/rpm form — produces an identifier that
// matches nothing, which is indistinguishable from a clean host.
func TestEcosystemPurlsAreTheShapeGrypeMatches(t *testing.T) {
	for _, tc := range []struct{ kind, name, version, want string }{
		// PEP 503: advisories key on the normalised name, so "Django" must
		// become "django" or it matches nothing. See the dedicated test below.
		{"pypi", "Django", "4.2.1", "pkg:pypi/django@4.2.1"},
		{"npm", "lodash", "4.17.20", "pkg:npm/lodash@4.17.20"},
		// A scoped npm package keeps its scope as a namespace.
		{"npm", "@angular/core", "15.2.0", "pkg:npm/%40angular/core@15.2.0"},
	} {
		got := ecoPurl(ecoPackage{Kind: tc.kind, Name: tc.name, Version: tc.version})
		if got != tc.want {
			t.Errorf("ecoPurl(%s %s) = %q, want %q", tc.kind, tc.name, got, tc.want)
		}
		if strings.Contains(got, "distro=") || strings.Contains(got, "arch=") {
			t.Errorf("%q carries a distro/arch qualifier; those belong to deb/rpm "+
				"purls only and stop grype matching", got)
		}
	}
}

func TestIncompleteEcosystemEntriesAreDropped(t *testing.T) {
	for _, e := range []ecoPackage{
		{Kind: "pypi", Name: "Django"},  // no version
		{Kind: "npm", Version: "1.0.0"}, // no name
		{Name: "x", Version: "1"},       // no kind
	} {
		if got := ecoPurl(e); got != "" {
			t.Errorf("ecoPurl(%+v) = %q, want empty — a half-identified package "+
				"matches the wrong thing or nothing, and both are worse than absent", e, got)
		}
	}
}

// One SBOM, both sources, no duplicates.
func TestSBOMCarriesBothSources(t *testing.T) {
	inv := parseInventory(strings.Join([]string{
		"#os\tdebian\t12", "#fmt\tdeb",
		"curl\t7.88.1-10\tamd64",
		"#pypi\tDjango\t4.2.1",
		"#pypi\tDjango\t4.2.1", // the same find reported twice
	}, "\n"))

	raw, n := buildLinuxSBOM("web01", inv)
	if n != 2 {
		t.Fatalf("components = %d, want 2 (curl + Django, deduped)", n)
	}
	var bom struct {
		Components []struct{ Name, Purl string } `json:"components"`
	}
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatal(err)
	}
	var sawDeb, sawPypi bool
	for _, c := range bom.Components {
		if strings.HasPrefix(c.Purl, "pkg:deb/") {
			sawDeb = true
		}
		if strings.HasPrefix(c.Purl, "pkg:pypi/") {
			sawPypi = true
		}
	}
	if !sawDeb || !sawPypi {
		t.Errorf("SBOM missing a source: deb=%v pypi=%v", sawDeb, sawPypi)
	}
}

// PyPI spells a project name two ways and only one of them matches.
//
// A dist-info directory carries the ESCAPED name — python_dateutil-2.9.0.dist-info
// — while advisories and grype's matcher use the PEP 503 normalised form,
// python-dateutil. Found on a real host: the collector returned
// "#pypi python_dateutil 2.9.0.post0", which as a purl matches nothing at all.
//
// That is the dangerous shape of wrong: a package that matches nothing looks
// exactly like a package with no vulnerabilities.
func TestPyPINamesAreNormalisedBeforeMatching(t *testing.T) {
	for raw, want := range map[string]string{
		"python_dateutil":  "python-dateutil",
		"Django":           "django",
		"zope.interface":   "zope-interface",
		"ruamel.yaml.clib": "ruamel-yaml-clib",
		"already-fine":     "already-fine",
		"Mixed_Case.Name":  "mixed-case-name",
		"double__sep":      "double-sep", // a run collapses to one hyphen
	} {
		if got := normalizePyPIName(raw); got != want {
			t.Errorf("normalizePyPIName(%q) = %q, want %q", raw, got, want)
		}
	}

	if got := ecoPurl(ecoPackage{Kind: "pypi", Name: "python_dateutil", Version: "2.9.0"}); got != "pkg:pypi/python-dateutil@2.9.0" {
		t.Errorf("purl = %q, want pkg:pypi/python-dateutil@2.9.0", got)
	}
	// npm is case-sensitive and does NOT normalise — applying PEP 503 there
	// would break a package legitimately named with a dot or capital.
	if got := ecoPurl(ecoPackage{Kind: "npm", Name: "socket.io", Version: "4.0.0"}); got != "pkg:npm/socket.io@4.0.0" {
		t.Errorf("npm purl = %q; npm names must be left alone", got)
	}
}
