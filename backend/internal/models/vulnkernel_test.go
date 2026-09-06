package models

import "testing"

// The real arrangement from a Debian 13 host, which is what makes this worth
// special-casing at all: `linux-cpupower` and `libcpupower1` are a CPU-frequency
// helper and its shared library, both built from the `linux` source package. The
// Debian security tracker keys kernel CVEs on that source, so grype matched 227
// critical+high kernel CVEs against them — 41% of the host's total — while the
// installed linux-image-* packages matched NOTHING, because Debian's signed images
// build from `linux-signed-amd64`, which the tracker does not key on.
//
// So the host's kernel CVE list arrives filed under a frequency utility. These are
// real vulnerabilities and must not be dropped; they must be attributed to the
// kernel and labelled with the version actually matched.
func TestIsKernelSourceFindingCatchesUserspaceHelpers(t *testing.T) {
	for _, pkg := range []string{"libcpupower1", "linux-cpupower", "linux-headers-6.12.105+deb13-amd64",
		"linux-kbuild-6.12.105+deb13", "linux-libc-dev", "linux-base"} {
		f := VulnFinding{CVE: "CVE-2025-40074", Package: pkg, SourcePackage: "linux",
			Severity: "Critical", CVSSScore: 9.8}
		if !IsKernelSourceFinding(f) {
			t.Errorf("IsKernelSourceFinding(%q from source linux) = false, want true — "+
				"this is a kernel CVE attributed to a userspace helper", pkg)
		}
	}
}

// The kernel itself is attributed correctly already; labelling it as misattributed
// would be its own kind of wrong.
func TestIsKernelSourceFindingLeavesTheKernelAlone(t *testing.T) {
	for _, pkg := range []string{"linux-image-6.12.105+deb13-amd64", "linux-image-amd64",
		"kernel-core", "kernel-modules-extra"} {
		f := VulnFinding{CVE: "CVE-2025-40074", Package: pkg, SourcePackage: "linux"}
		if IsKernelSourceFinding(f) {
			t.Errorf("IsKernelSourceFinding(%q) = true, want false — this IS the kernel", pkg)
		}
	}
}

// Everything else must be left alone. A package that merely starts with "lib" or
// happens to sit near the kernel in a package list is not a kernel finding.
func TestIsKernelSourceFindingIgnoresNonKernelSources(t *testing.T) {
	cases := []VulnFinding{
		{Package: "libcurl4t64", SourcePackage: "curl"},
		{Package: "perl-base", SourcePackage: "perl"},
		{Package: "libcpupower1", SourcePackage: ""},           // pre-capture scan: no source known
		{Package: "linux-cpupower", SourcePackage: "cpupower"}, // hypothetical split-out source
	}
	for _, f := range cases {
		if IsKernelSourceFinding(f) {
			t.Errorf("IsKernelSourceFinding(%q from %q) = true, want false", f.Package, f.SourcePackage)
		}
	}
}

// Grouping key: the source package when known, the binary package otherwise. Scans
// recorded before source capture must still group into something sensible rather
// than collapsing into one empty-named bucket.
func TestVulnComponentFallsBackToBinaryPackage(t *testing.T) {
	if got := VulnComponent(VulnFinding{Package: "libcpupower1", SourcePackage: "linux"}); got != "linux" {
		t.Errorf("VulnComponent = %q, want %q", got, "linux")
	}
	if got := VulnComponent(VulnFinding{Package: "libcpupower1"}); got != "libcpupower1" {
		t.Errorf("VulnComponent with no source = %q, want the binary name", got)
	}
	if got := VulnComponent(VulnFinding{Package: "openssl", SourcePackage: "  "}); got != "openssl" {
		t.Errorf("VulnComponent with blank source = %q, want the binary name", got)
	}
}
