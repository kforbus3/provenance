"""Tests for the grype-scanner sidecar's normalization of grype output.

Run: make scanner-test  (or: python -m pytest deploy/grype-scanner)

Only the pure functions are covered here — the endpoints shell out to grype and to
a multi-hundred-megabyte vulnerability database, which is an integration concern.
The parsing is what silently returns the wrong thing.
"""

from app import _best_cvss, _normalize, _source_package


# Debian ships the kernel's userspace helpers from the `linux` source package, so
# grype resolves libcpupower1 -> linux and matches the whole kernel CVE list against
# it. Losing this field is what left 227 kernel CVEs filed under a CPU-frequency
# utility with nothing to group or relabel them by.
def test_source_package_from_upstreams():
    a = {"name": "libcpupower1", "version": "6.12.105-1",
         "upstreams": [{"name": "linux", "version": "6.12.105-1"}]}
    assert _source_package(a) == "linux"


def test_source_package_falls_back_to_dpkg_metadata():
    a = {"name": "libc6", "metadata": {"type": "DpkgMetadata", "source": "glibc"}}
    assert _source_package(a) == "glibc"


# upstreams wins when both are present: it is syft's current field and the one that
# stays correct when the dpkg source carries an explicit version ("linux (6.12.1)").
def test_source_package_prefers_upstreams_over_metadata():
    a = {"name": "libc6", "upstreams": [{"name": "glibc"}],
         "metadata": {"source": "glibc-stale"}}
    assert _source_package(a) == "glibc"


# rpm reports a source FILENAME, not a name. Trimming has to remove `.src.rpm` and
# then the version-release the filename carries — while leaving hyphenated package
# names intact, which a naive split on "-" destroys.
def test_source_package_trims_source_rpm_filename():
    assert _source_package({"metadata": {"sourceRpm": "glibc-2.39-5.el9.src.rpm"}}) == "glibc"
    assert _source_package(
        {"metadata": {"sourceRpm": "python3-setuptools-68.0-3.el9.src.rpm"}}
    ) == "python3-setuptools"


def test_source_package_absent_is_empty_not_an_error():
    assert _source_package({"name": "openssl"}) == ""
    assert _source_package({}) == ""
    # An upstream entry with a blank name must not win over the metadata fallback.
    assert _source_package({"upstreams": [{"name": "  "}],
                            "metadata": {"source": "openssl"}}) == "openssl"


# Distro sources carry a severity but usually no numeric CVSS; grype attaches the
# NVD record under relatedVulnerabilities. Preferring v3/v4 over v2 matters because
# the two scoring systems disagree by whole severity bands.
def test_best_cvss_prefers_v3_over_v2():
    score, vector = _best_cvss([
        {"version": "2.0", "metrics": {"baseScore": 10.0}, "vector": "AV:N/AC:L"},
        {"version": "3.1", "metrics": {"baseScore": 7.5}, "vector": "CVSS:3.1/AV:N"},
    ])
    assert score == 7.5
    assert vector == "CVSS:3.1/AV:N"


def test_best_cvss_survives_malformed_scores():
    assert _best_cvss([{"version": "3.1", "metrics": {"baseScore": "not-a-number"}}]) == (0.0, "")
    assert _best_cvss(None) == (0.0, "")


# A concrete fixed version means a fix exists whatever the tracker labelled it; an
# EMPTY version must keep the tracker's own distinction, because "not shipped yet"
# and "we will never fix this" are opposite answers to "is there work here".
def test_normalize_carries_fix_state_and_source():
    out = _normalize({"matches": [
        {"vulnerability": {"id": "CVE-1", "severity": "Critical",
                           "fix": {"versions": [], "state": "wont-fix"}},
         "artifact": {"name": "libcpupower1", "version": "6.12.105-1",
                      "upstreams": [{"name": "linux"}]}},
        {"vulnerability": {"id": "CVE-2", "severity": "High",
                           "fix": {"versions": ["8.5.0-1"], "state": "unknown"}},
         "artifact": {"name": "curl", "version": "8.4.0-1"}},
    ]})
    kernel, curl = out["findings"]
    assert kernel["fixState"] == "wont-fix"
    assert kernel["sourcePackage"] == "linux"
    assert curl["fixState"] == "fixed", "a concrete fixed version is a fix regardless of label"
    assert curl["fixedVersion"] == "8.5.0-1"
    assert curl["sourcePackage"] == ""


def test_normalize_empty_state_reads_as_unknown():
    out = _normalize({"matches": [
        {"vulnerability": {"id": "CVE-1", "severity": "Low", "fix": {}}, "artifact": {"name": "a"}},
    ]})
    assert out["findings"][0]["fixState"] == "unknown"
