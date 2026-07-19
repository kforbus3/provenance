"""Fleet Terminal — grype-scanner sidecar.

A small internal HTTP service the Fleet backend calls to run vulnerability scans.
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
import json
import os
import subprocess
import tarfile
import tempfile

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

app = FastAPI(title="fleet-grype-scanner", version="1")

SCAN_TIMEOUT = int(os.environ.get("GRYPE_SCAN_TIMEOUT", "300"))
DB_TIMEOUT = int(os.environ.get("GRYPE_DB_TIMEOUT", "900"))
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
        fixed = ";".join((v.get("fix") or {}).get("versions") or [])
        findings.append({
            "cve": v.get("id", ""),
            "severity": v.get("severity") or "Unknown",
            "package": a.get("name", ""),
            "installedVersion": a.get("version", ""),
            "fixedVersion": fixed,
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
            proc = subprocess.run(
                ["grype", f"dir:{root}", "-o", "json"],
                capture_output=True, timeout=SCAN_TIMEOUT, env=BASE_ENV,
            )
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
        proc = subprocess.run(
            ["grype", f"sbom:{path}", "-o", "json"],
            capture_output=True, timeout=SCAN_TIMEOUT, env=BASE_ENV,
        )
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
