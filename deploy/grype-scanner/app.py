"""Provenance — grype-scanner sidecar.

A small internal HTTP service the Provenance backend calls to run vulnerability scans.
It wraps Anchore Grype so the (large) vulnerability database and the scanner live
in their own container, out of the lean Go backend.

The backend collects each host's package databases over SSH and posts them here as
a gzip tarball; the sidecar runs grype against them and returns normalized CVE
findings with CVSS scores. It never connects to any managed host itself.

Endpoints:
  GET  /healthz     liveness
  POST /scan        gzip tar of a host's package DBs -> findings JSON
  GET  /db/status   grype vulnerability-DB status (text)
  POST /db/update   update the vulnerability DB online (needs sidecar internet)
  POST /db/import   import a pre-downloaded DB archive (offline / air-gapped)
"""

import io
import asyncio
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

app = FastAPI(title="prov-grype-scanner", version="1")

# Per-scan wall-clock cap. Default aligns with the backend's PROV_VULN_SCAN_TIMEOUT
# (20m) so the scanner never 504s before the backend would wait — a host with a large
# package database (e.g. an ML/CUDA box) can legitimately take several minutes.
SCAN_TIMEOUT = int(os.environ.get("GRYPE_SCAN_TIMEOUT", "1200"))
DB_TIMEOUT = int(os.environ.get("GRYPE_DB_TIMEOUT", "900"))

# grype is CPU/memory-heavy (it loads the vuln DB per run). A scheduled "scan all
# hosts" fans many requests here at once, so bound how many grype processes run
# concurrently and run each OFF the event loop (asyncio.to_thread). Without this,
# a single blocking subprocess.run inside an async handler froze the lone uvicorn
# worker and serialized every scan — so a fleet-wide scan timed out at the back of
# the queue. Extra requests now wait on the semaphore with the loop free, instead
# of blocking the whole worker.
SCAN_CONCURRENCY = int(os.environ.get("GRYPE_SCAN_CONCURRENCY", "2"))
_scan_sem = asyncio.Semaphore(max(1, SCAN_CONCURRENCY))


# Where each run's scratch space goes. grype (via stereoscope/syft) extracts whole
# image layers and package databases here, which for a container image is gigabytes.
SCAN_TMP_ROOT = os.environ.get("GRYPE_TMP_ROOT", tempfile.gettempdir())

# Anything older than this was left by a run that is certainly over.
STALE_TMP_AGE = max(2 * SCAN_TIMEOUT, 3600)

# The prefixes grype's own libraries use, plus ours.
_TMP_PREFIXES = ("prov-scan-", "stereoscope-", "syft-cataloger-")


def _sweep_scan_temp(root: str = SCAN_TMP_ROOT, max_age: int = STALE_TMP_AGE) -> int:
    """Delete scratch trees an earlier run left behind. Returns bytes freed.

    These accumulate because of how a timeout kills a scan: subprocess.run sends
    SIGKILL, so stereoscope's deferred cleanup never runs and its extracted layers
    stay on disk forever. On this fleet that reached 6.6GB inside the scanner
    container -- most of a 92GB root filesystem -- with nothing in any log to say
    where the space had gone.
    Only trees older than max_age are touched, so a scan in flight is never
    disturbed: a running scan's directory is at most SCAN_TIMEOUT old.
    """
    freed = 0
    now = time.time()
    try:
        entries = os.listdir(root)
    except OSError:
        return 0
    for name in entries:
        if not name.startswith(_TMP_PREFIXES):
            continue
        path = os.path.join(root, name)
        try:
            if now - os.stat(path).st_mtime < max_age:
                continue
            for dirpath, _dirs, files in os.walk(path):
                for fn in files:
                    try:
                        freed += os.lstat(os.path.join(dirpath, fn)).st_size
                    except OSError:
                        pass
            shutil.rmtree(path, ignore_errors=True)
        except OSError:
            continue
    return freed


async def _run_grype(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Run grype off the event loop, bounded by the concurrency semaphore.

    The sweep runs here rather than at startup: this container runs for weeks, so a
    startup hook would fire once and never again, and anything leaked in between
    would sit there until someone noticed 7GB missing. A scan is also the only
    moment the scratch space matters.

    Each run gets its own TMPDIR, removed in a finally -- which is the difference
    between a scan that is killed and one that leaks. subprocess.run raises
    TimeoutExpired after SIGKILLing grype, so nothing grype registered to clean up
    ever runs; giving it a directory we own means the cleanup is ours to guarantee.
    """
    async with _scan_sem:
        _sweep_scan_temp()
        tmp = tempfile.mkdtemp(prefix="prov-scan-", dir=SCAN_TMP_ROOT)
        env = {**BASE_ENV, "TMPDIR": tmp}
        try:
            return await asyncio.to_thread(
                subprocess.run, args, capture_output=True, timeout=timeout, env=env
            )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
MAX_SCAN_UPLOAD = int(os.environ.get("GRYPE_MAX_SCAN_BYTES", str(256 << 20)))   # host package DBs
MAX_DB_UPLOAD = int(os.environ.get("GRYPE_MAX_DB_BYTES", str(2 << 30)))          # DB archive can be ~1GB

# Never auto-update mid-scan: DB refresh is explicit (so air-gapped works and scans
# are deterministic).
BASE_ENV = {**os.environ, "GRYPE_DB_AUTO_UPDATE": "false"}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


def _safe_extract(tf: tarfile.TarFile, dest: str) -> None:
    """Extract a tar, refusing any member that would escape dest (path traversal)."""
    base = os.path.realpath(dest)
    for m in tf.getmembers():
        target = os.path.realpath(os.path.join(dest, m.name))
        if target != base and not target.startswith(base + os.sep):
            raise ValueError(f"unsafe path in archive: {m.name}")
        if m.issym() or m.islnk():
            raise ValueError(f"links not allowed in archive: {m.name}")
    tf.extractall(dest)


def _best_cvss(cvss_list):
    """Return the highest CVSS base score + its vector, preferring v3/v4."""
    best_score, best_vec, best_ver = 0.0, "", 0
    for c in cvss_list or []:
        try:
            score = float((c.get("metrics") or {}).get("baseScore", 0) or 0)
        except (TypeError, ValueError):
            score = 0.0
        ver = str(c.get("version", ""))
        vnum = 3 if ver.startswith("3") else 4 if ver.startswith("4") else 2 if ver.startswith("2") else 0
        if (vnum, score) > (best_ver, best_score):
            best_score, best_vec, best_ver = score, c.get("vector", "") or "", vnum
    return round(best_score, 1), best_vec


def _source_package(a: dict) -> str:
    """The SOURCE package an artifact was built from, or "" if not reported.

    Distro CVE trackers key on the source package, so grype matches a binary by
    resolving it to its source first: every binary built from `linux` inherits the
    entire kernel CVE list, and eight binaries from one source repeat the same CVE
    eight times. Carrying the source through is what lets the UI group those and
    name what is actually vulnerable.

    Three shapes, newest first: syft's `upstreams` (current), the dpkg metadata
    `source` field, and an rpm `sourceRpm` filename that has to be trimmed back to
    a bare name (`glibc-2.39-5.el9.src.rpm` -> `glibc`).
    """
    for u in a.get("upstreams") or []:
        if (u.get("name") or "").strip():
            return u["name"].strip()
    meta = a.get("metadata") or {}
    if (meta.get("source") or "").strip():
        return meta["source"].strip()
    srpm = (meta.get("sourceRpm") or "").strip()
    if srpm:
        # Strip .src.rpm, then the trailing -version-release the filename carries.
        stem = srpm[: -len(".src.rpm")] if srpm.endswith(".src.rpm") else srpm
        return stem.rsplit("-", 2)[0] if stem.count("-") >= 2 else stem
    return ""


def _normalize(g: dict) -> dict:
    findings = []
    for m in g.get("matches", []) or []:
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        # Distro sources (e.g. Debian, Ubuntu) carry a severity but usually no
        # numeric CVSS — grype attaches the NVD record (with CVSS) under
        # relatedVulnerabilities, so gather scores from both.
        cvss_all = list(v.get("cvss") or [])
        for rel in m.get("relatedVulnerabilities") or []:
            cvss_all += rel.get("cvss") or []
        score, vector = _best_cvss(cvss_all)
        fix = v.get("fix") or {}
        fixed = ";".join(fix.get("versions") or [])
        # The distro trackers say a lot more than "is there a version": "wont-fix"
        # (assessed, deliberately not fixed) and "not-fixed" (acknowledged, no fix
        # yet) both arrive with an empty version list and mean entirely different
        # things to whoever is triaging. Carry the state through instead of letting
        # both collapse into an empty fixedVersion.
        state = (fix.get("state") or "").strip().lower()
        if fixed and state not in ("fixed", "wont-fix", "not-fixed"):
            state = "fixed"  # a concrete version is a fix regardless of labelling
        findings.append({
            "cve": v.get("id", ""),
            "severity": v.get("severity") or "Unknown",
            "package": a.get("name", ""),
            "sourcePackage": _source_package(a),
            "installedVersion": a.get("version", ""),
            "fixedVersion": fixed,
            "fixState": state or "unknown",
            "cvssScore": score,
            "cvssVector": vector,
            "dataSource": v.get("dataSource", ""),
            "description": (v.get("description") or "")[:1000],
        })
    db = (g.get("descriptor") or {}).get("db") or {}
    built = db.get("built") or (db.get("status") or {}).get("built", "") if isinstance(db.get("status"), dict) else db.get("built", "")
    return {"findings": findings, "dbBuilt": built or ""}


@app.post("/scan")
async def scan(request: Request):
    body = await request.body()
    if not body:
        return JSONResponse({"error": "empty archive"}, status_code=400)
    if len(body) > MAX_SCAN_UPLOAD:
        return JSONResponse({"error": "payload too large"}, status_code=413)
    with tempfile.TemporaryDirectory() as root:
        try:
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tf:
                _safe_extract(tf, root)
        except Exception as e:  # noqa: BLE001 — any bad archive is a 400
            return JSONResponse({"error": f"bad archive: {e}"}, status_code=400)
        try:
            proc = await _run_grype(["grype", f"dir:{root}", "-o", "json"], SCAN_TIMEOUT)
        except subprocess.TimeoutExpired:
            return JSONResponse({"error": "scan timed out"}, status_code=504)
        if proc.returncode != 0:
            return JSONResponse({"error": proc.stderr.decode(errors="replace")[:2000]}, status_code=500)
        try:
            return JSONResponse(_normalize(json.loads(proc.stdout)))
        except json.JSONDecodeError:
            return JSONResponse({"error": "could not parse grype output"}, status_code=500)


@app.post("/scan-sbom")
async def scan_sbom(request: Request):
    """Scan a CycloneDX/SPDX SBOM (JSON) whose components carry CPEs.

    Used for Windows third-party apps: the backend inventories installed software,
    maps it to CPEs, and posts an SBOM here; grype matches the CPEs against NVD.
    """
    body = await request.body()
    if not body:
        return JSONResponse({"error": "empty sbom"}, status_code=400)
    if len(body) > MAX_SCAN_UPLOAD:
        return JSONResponse({"error": "payload too large"}, status_code=413)
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(body)
        path = f.name
    try:
        proc = await _run_grype(["grype", f"sbom:{path}", "-o", "json"], SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return JSONResponse({"error": "scan timed out"}, status_code=504)
    finally:
        os.remove(path)
    if proc.returncode != 0:
        return JSONResponse({"error": proc.stderr.decode(errors="replace")[:2000]}, status_code=500)
    try:
        return JSONResponse(_normalize(json.loads(proc.stdout)))
    except json.JSONDecodeError:
        return JSONResponse({"error": "could not parse grype output"}, status_code=500)


# A container image reference, pinned by digest.
#
# Digest-only, deliberately. A tag moves: scanning "nginx:1.25" tells you about
# whatever that tag points at NOW, which is not necessarily what the host is
# running -- and a report about an image nobody is running is worse than no
# report, because it is indistinguishable from one that matters. The inventory
# collects the resolved digest for exactly this reason, so the scan can be about
# the bytes actually in use.
#
# Bounded to what a registry reference can contain. grype is handed this as an
# argument, not through a shell, but an unbounded string reaching a subprocess
# argument list is not something to leave to the absence of a shell.
IMAGE_REF = re.compile(r"^[a-zA-Z0-9._:/-]{1,255}@sha256:[a-f0-9]{64}$")


@app.post("/scan-image")
async def scan_image(request: Request):
    """Scan a container image by digest-pinned reference.

    grype pulls the image from its registry itself -- there is no Docker daemon in
    this container and it needs none. That also means this reaches the network:
    a private registry needs credentials in the scanner's environment, and a rate
    limited one will say so in the error rather than silently returning nothing.
    """
    body = await request.body()
    try:
        ref = (json.loads(body or b"{}").get("image") or "").strip()
    except json.JSONDecodeError:
        return JSONResponse({"error": "invalid json"}, status_code=400)
    if not ref:
        return JSONResponse({"error": "image is required"}, status_code=400)
    if not IMAGE_REF.match(ref):
        return JSONResponse(
            {"error": "image must be a digest-pinned reference (repo@sha256:...)"},
            status_code=400,
        )
    try:
        proc = await _run_grype(["grype", f"registry:{ref}", "-o", "json"], SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return JSONResponse({"error": "scan timed out"}, status_code=504)
    if proc.returncode != 0:
        # Surfaced rather than flattened to "scan failed": the three things that
        # go wrong here -- no such image, no credentials, rate limited -- have
        # three different answers, and an operator cannot pick one from a generic
        # failure.
        return JSONResponse(
            {"error": proc.stderr.decode(errors="replace")[:2000]}, status_code=502)
    try:
        return JSONResponse(_normalize(json.loads(proc.stdout)))
    except json.JSONDecodeError:
        return JSONResponse({"error": "could not parse grype output"}, status_code=500)


@app.get("/db/status")
def db_status():
    proc = subprocess.run(["grype", "db", "status"], capture_output=True, env=BASE_ENV, timeout=60)
    return PlainTextResponse((proc.stdout + proc.stderr).decode(errors="replace"))


@app.post("/db/update")
def db_update():
    env = {**BASE_ENV, "GRYPE_DB_AUTO_UPDATE": "true"}
    proc = subprocess.run(["grype", "db", "update"], capture_output=True, env=env, timeout=DB_TIMEOUT)
    ok = proc.returncode == 0
    return JSONResponse(
        {"ok": ok, "output": (proc.stdout + proc.stderr).decode(errors="replace")[:4000]},
        status_code=200 if ok else 502,
    )


@app.post("/db/import")
async def db_import(request: Request):
    body = await request.body()
    if not body:
        return JSONResponse({"error": "empty archive"}, status_code=400)
    if len(body) > MAX_DB_UPLOAD:
        return JSONResponse({"error": "archive too large"}, status_code=413)
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as f:
        f.write(body)
        path = f.name
    try:
        proc = subprocess.run(["grype", "db", "import", path], capture_output=True, env=BASE_ENV, timeout=DB_TIMEOUT)
    finally:
        os.remove(path)
    ok = proc.returncode == 0
    return JSONResponse(
        {"ok": ok, "output": (proc.stdout + proc.stderr).decode(errors="replace")[:4000]},
        status_code=200 if ok else 400,
    )
