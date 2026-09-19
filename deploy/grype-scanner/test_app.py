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


# --- /scan-image reference validation ----------------------------------------
#
# The reference reaches grype as a subprocess argument. There is no shell, so
# this is not about injection so much as about scanning the right thing: a
# reference that is not digest-pinned scans whatever a tag points at NOW, which
# is not necessarily what any host is running. A report about an image nobody
# runs is worse than no report, because it looks exactly like one that matters.

def test_image_ref_requires_a_digest():
    from app import IMAGE_REF
    sha = "a" * 64

    good = [
        f"nginx@sha256:{sha}",
        f"qmcgaw/gluetun@sha256:{sha}",
        f"ghcr.io/owner/app@sha256:{sha}",
        # A registry with a port is a normal reference and must be accepted.
        f"registry.example.com:5000/app@sha256:{sha}",
    ]
    for ref in good:
        assert IMAGE_REF.match(ref), f"should accept {ref}"

    bad = [
        "nginx",                       # no digest at all
        "nginx:1.25",                  # a tag moves; this is the whole point
        f"nginx@sha512:{sha}",         # only sha256 is what a registry gives us
        f"nginx@sha256:{'a' * 63}",    # truncated digest
        f"nginx@sha256:{'A' * 64}",    # digests are lowercase hex
        f"nginx@sha256:{sha} extra",   # trailing junk
        f"nginx;id@sha256:{sha}",      # shell metacharacters have no business here
        f"$(id)@sha256:{sha}",
        "",
    ]
    for ref in bad:
        assert not IMAGE_REF.match(ref), f"should reject {ref!r}"


# --- scratch-space cleanup ---------------------------------------------------
#
# The scanner's writable layer reached 7GB on this fleet, 6.6GB of it /tmp, with
# nothing in any log to say where the space had gone. The mechanism: a scan that
# exceeds GRYPE_SCAN_TIMEOUT is SIGKILLed by subprocess.run, so stereoscope's
# deferred cleanup never runs and the image layers it extracted stay forever. Each
# run now gets a TMPDIR removed in a finally, and this sweep clears anything an
# earlier version (or a hard crash) left behind.

import os
import time

from app import _sweep_scan_temp


def _tree(root, name, age_s, size=2048):
    d = os.path.join(root, name)
    os.makedirs(os.path.join(d, "layer"), exist_ok=True)
    f = os.path.join(d, "layer", "blob")
    with open(f, "wb") as fh:
        fh.write(b"\0" * size)
    old = time.time() - age_s
    os.utime(d, (old, old))
    return d


def test_sweep_removes_stale_trees_and_reports_what_it_freed(tmp_path):
    root = str(tmp_path)
    stale = _tree(root, "stereoscope-123", age_s=7200)
    syft = _tree(root, "syft-cataloger-456", age_s=7200)

    freed = _sweep_scan_temp(root=root, max_age=3600)

    assert not os.path.exists(stale)
    assert not os.path.exists(syft)
    assert freed >= 4096, "should report the bytes it reclaimed, not just delete"


def test_sweep_leaves_a_scan_that_is_still_running(tmp_path):
    """A running scan's directory is at most SCAN_TIMEOUT old. Deleting it would
    break a scan that is working, which is worse than the disk usage."""
    root = str(tmp_path)
    fresh = _tree(root, "prov-scan-inflight", age_s=60)

    _sweep_scan_temp(root=root, max_age=3600)

    assert os.path.exists(fresh), "swept a scan that was still running"


def test_sweep_ignores_anything_it_did_not_create(tmp_path):
    """/tmp is shared. Only the known prefixes are ours to delete."""
    root = str(tmp_path)
    other = _tree(root, "someone-elses-data", age_s=99999)

    _sweep_scan_temp(root=root, max_age=3600)

    assert os.path.exists(other), "deleted a directory belonging to something else"
