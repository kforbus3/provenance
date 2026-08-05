package vulnscan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseInventoryDebian(t *testing.T) {
	out := strings.Join([]string{
		"#os\tdebian\t12",
		"#fmt\tdeb",
		"curl\t7.88.1-10+deb12u5\tamd64",
		"libc6\t2.36-9+deb12u7\tamd64",
		"libc6\t2.36-9+deb12u7\ti386",
	}, "\n")
	inv := parseInventory(out)

	if inv.OSID != "debian" || inv.OSVersion != "12" {
		t.Fatalf("os = %q %q", inv.OSID, inv.OSVersion)
	}
	if inv.Format != "deb" {
		t.Fatalf("format = %q", inv.Format)
	}
	if len(inv.Packages) != 3 {
		t.Fatalf("got %d packages, want 3", len(inv.Packages))
	}
}

func TestParseInventoryTolerance(t *testing.T) {
	// A malformed row must not cost the whole inventory: this runs after a
	// successful scan and losing the SBOM over one odd line is a bad trade.
	out := strings.Join([]string{
		"#os\trocky\t9",
		"#fmt\trpm",
		"good\t1.0-1\tx86_64",
		"truncated-row",
		"",
		"\t\t",
		"also-good\t2.0-1\tnoarch",
	}, "\n")
	inv := parseInventory(out)
	if len(inv.Packages) != 2 {
		t.Fatalf("got %d packages, want 2: %+v", len(inv.Packages), inv.Packages)
	}
}

func TestParseInventoryNoPackageManager(t *testing.T) {
	inv := parseInventory("#os\talpine\t3.19\n#fmt\tnone\n")
	if inv.Format != "" {
		t.Fatalf("format = %q, want empty so no SBOM is claimed", inv.Format)
	}
	if len(inv.Packages) != 0 {
		t.Fatal("packages reported for a host with no supported package manager")
	}
}

// Debian versions routinely contain epochs (2:1.4) and build suffixes
// (1.2+deb12u1). Both characters are legal in a purl and escaping them would
// produce identifiers no consumer matches.
func TestPurlKeepsEpochAndPlus(t *testing.T) {
	inv := inventory{OSID: "debian", OSVersion: "12", Format: "deb"}
	got := purl(inv, invPackage{Name: "libpython3.11", Version: "2:3.11.2+deb12u1", Arch: "amd64"})
	want := "pkg:deb/debian/libpython3.11@2:3.11.2+deb12u1?arch=amd64&distro=debian-12"
	if got != want {
		t.Fatalf("purl =\n  %s\nwant\n  %s", got, want)
	}
}

func TestPurlEscapesStructuralCharacters(t *testing.T) {
	inv := inventory{OSID: "debian", OSVersion: "12", Format: "deb"}
	got := purl(inv, invPackage{Name: "odd/name", Version: "1 0", Arch: "amd64"})
	if strings.Contains(got, "odd/name") {
		t.Fatalf("an unescaped slash would split the purl namespace: %s", got)
	}
	if strings.Contains(got, "1 0") {
		t.Fatalf("an unescaped space leaked into the purl: %s", got)
	}
}

func TestPurlEmptyWithoutFormat(t *testing.T) {
	if got := purl(inventory{OSID: "debian"}, invPackage{Name: "x", Version: "1"}); got != "" {
		t.Fatalf("purl = %q, want empty when no package manager was identified", got)
	}
}

func TestBuildLinuxSBOMIncludesEveryPackage(t *testing.T) {
	inv := inventory{
		OSID: "debian", OSVersion: "12", Format: "deb",
		Packages: []invPackage{
			{"curl", "7.88.1-10", "amd64"},
			{"zlib1g", "1:1.2.13", "amd64"},
			// Same name, different architecture: multi-arch installs both, and
			// both are genuinely present.
			{"zlib1g", "1:1.2.13", "i386"},
		},
	}
	doc, n := buildLinuxSBOM("web01", inv)
	if n != 3 {
		t.Fatalf("components = %d, want 3 (multi-arch duplicates are distinct)", n)
	}

	var bom cdxBOM
	if err := json.Unmarshal(doc, &bom); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.5" {
		t.Fatalf("bad header: %s %s", bom.BOMFormat, bom.SpecVersion)
	}
	// Without a subject a consumer ingesting many of these cannot tell which
	// machine each describes.
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		t.Fatal("no metadata.component identifying the host")
	}
	if bom.Metadata.Component.Name != "web01" {
		t.Fatalf("subject = %q, want web01", bom.Metadata.Component.Name)
	}
	for _, c := range bom.Components {
		if c.PURL == "" {
			t.Fatalf("component %s has no purl", c.Name)
		}
		if c.CPE != "" {
			t.Fatalf("component %s carries a CPE; Linux identity is a purl", c.Name)
		}
	}
}

// A bill of materials answers "what is on this machine", so it must include
// packages no scanner can match — not only the ones with known vulnerabilities.
func TestBuildLinuxSBOMDoesNotFilter(t *testing.T) {
	inv := inventory{OSID: "debian", OSVersion: "12", Format: "deb"}
	for i := 0; i < 50; i++ {
		inv.Packages = append(inv.Packages, invPackage{
			Name: "obscure-package-" + string(rune('a'+i%26)), Version: "1.0", Arch: "all",
		})
	}
	if _, n := buildLinuxSBOM("h", inv); n == 0 {
		t.Fatal("no components emitted; a BOM is not a vulnerability report")
	}
}

func TestBuildLinuxSBOMEmptyInventory(t *testing.T) {
	doc, n := buildLinuxSBOM("h", inventory{OSID: "debian", Format: "deb"})
	if n != 0 {
		t.Fatalf("components = %d, want 0", n)
	}
	// Still valid JSON, so a caller that stores it unconditionally cannot write
	// a broken document — though saveSBOM declines to store an empty one.
	var bom cdxBOM
	if err := json.Unmarshal(doc, &bom); err != nil {
		t.Fatalf("empty inventory produced invalid JSON: %v", err)
	}
}

func TestSanitizeFilename(t *testing.T) {
	// Hostnames come from enrollment and are not guaranteed tame. A quote or a
	// newline here would let a host name inject a Content-Disposition header.
	for _, tc := range []struct{ in, want string }{
		{"web01.example.com", "web01.example.com"},
		{`evil"; drop`, "evil---drop"},
		{"line\nbreak", "line-break"},
		{"", "host"},
	} {
		if got := sanitizeFilename(tc.in); got != tc.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if len(sanitizeFilename(strings.Repeat("a", 200))) != 64 {
		t.Error("long hostname was not truncated")
	}
}
