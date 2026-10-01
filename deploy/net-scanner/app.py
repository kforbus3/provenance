"""Provenance — net-scanner sidecar.

The network half of vulnerability scanning. grype answers "what is installed and
vulnerable" from inside a host; this answers what grype cannot see from outside it:
which ports actually answer, what is serving on them, and whether that service is
vulnerable or misconfigured -- weak TLS, weak SSH algorithms, unauthenticated
databases, exposed admin panels, management interfaces that should not be on the
network at all.

It wraps three MIT/Apache-licensed tools:

  naabu        port discovery (TCP connect scan -- no raw sockets, no NET_RAW)
  fingerprintx service identification on each open port
  nuclei       vulnerability and misconfiguration checks (community templates)

plus two UDP probes nuclei has no template for (IPMI/BMC and SSDP).

Endpoints (every one except /healthz requires the X-Netscan-Token header):
  GET  /healthz            liveness, overlay route, template presence
  POST /scan               scan one IP address -> services + findings JSON
  POST /discover           live addresses in a CIDR (for range scans)
  GET  /templates/status   nuclei template version and age
  POST /templates/update   refresh templates online (needs sidecar internet)
  POST /templates/import   install a templates tarball (offline / air-gapped)

Safe by default, and not configurable to be otherwise: nothing that guesses
credentials, fuzzes, or is tagged disruptive is ever run. This scanner looks at
exposure and configuration; it never tries to log in to anything.
"""

import asyncio
import hmac
import io
import ipaddress
import itertools
import json
import os
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import time

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import probes



@asynccontextmanager
async def _lifespan(_app):
    pin_nuclei_config()
    yield


app = FastAPI(title="prov-net-scanner", version="1", lifespan=_lifespan)

TOKEN = os.environ.get("NETSCAN_TOKEN", "")
# Development only: the test fabric runs without secrets. Never set in production --
# in the single-server layout this API shares the jump host's network namespace, and
# the token is what keeps a managed host on the overlay from driving the scanner.
ALLOW_NO_TOKEN = os.environ.get("NETSCAN_ALLOW_NO_TOKEN", "") == "1"

TEMPLATES_DIR = os.environ.get("NETSCAN_TEMPLATES_DIR", "/home/scanner/nuclei-templates")
# Packets per second for the port sweep. 1000 covers all 65535 TCP ports of one
# address in a little over a minute, and is gentle enough for a home router's
# connection tracking.
PORT_RATE = int(os.environ.get("NETSCAN_PORT_RATE", "1000"))
# Requests per second nuclei may send to one target.
NUCLEI_RATE = int(os.environ.get("NETSCAN_NUCLEI_RATE", "100"))
# Addresses scanned at once. Each scan is a port sweep plus several nuclei passes.
CONCURRENCY = int(os.environ.get("NETSCAN_CONCURRENCY", "2"))
# Wall-clock cap for one address, end to end.
SCAN_TIMEOUT = int(os.environ.get("NETSCAN_TIMEOUT", "1800"))
TEMPLATES_TIMEOUT = int(os.environ.get("NETSCAN_TEMPLATES_TIMEOUT", "900"))
MAX_TEMPLATES_UPLOAD = int(os.environ.get("NETSCAN_MAX_TEMPLATES_BYTES", str(512 << 20)))
# The overlay network the jump host serves (WireGuard or OpenVPN). When set, /healthz
# reports whether this container can route to it -- in the single-server layout it
# shares the jump host's network namespace precisely so that it can.
OVERLAY_CIDR = os.environ.get("NETSCAN_OVERLAY_CIDR", "")
REQUIRE_OVERLAY = os.environ.get("NETSCAN_REQUIRE_OVERLAY", "") == "1"
# Identifies the traffic in the target's own logs. A scan that looks like an
# anonymous browser is a scan nobody can tell apart from an attack.
USER_AGENT = os.environ.get("NETSCAN_USER_AGENT", "Provenance-NetScan/1")
# Largest range /discover accepts. A /22 is 1024 addresses.
MAX_RANGE_ADDRESSES = int(os.environ.get("NETSCAN_MAX_RANGE_ADDRESSES", "1024"))

_scan_sem = asyncio.Semaphore(max(1, CONCURRENCY))
_templates_lock = threading.Lock()

# --- safety policy ---------------------------------------------------------------

# Never run. dos/fuzz/intrusive are the obvious ones. bruteforce and default-login
# are excluded because they try credentials: on a managed fleet that means failed
# logins in every auth log, and on Windows or LDAP it means locked accounts.
EXCLUDED_TAGS = [
    "dos", "fuzz", "fuzzing", "intrusive", "bruteforce", "brute-force",
    "default-login", "default-logins",
]
# Never run either: protocols that execute code on the scanner, drive a browser,
# read local files, or query third parties about the target.
EXCLUDED_PROTOCOLS = ["code", "headless", "file", "dns", "whois", "workflow"]
# Whole directories with the same character as the tags above.
EXCLUDED_DIRS = [
    "dast", "http/fuzzing", "javascript/default-logins", "network/default-login",
]
# A template that iterates a username or password wordlist is guessing credentials
# whatever it is tagged. Found by scanning the templates themselves, so a new one is
# excluded the day it arrives rather than the day someone notices.
_CRED_WORDLIST = re.compile(r"helpers/wordlists/[^\s\"']*(user|pass|cred|login|token)", re.I)

# Tags for the HTTP pass that does not depend on technology detection: things worth
# checking on any web server, whatever it turns out to be.
HTTP_GENERIC_TAGS = [
    "exposure", "misconfig", "panel", "unauth", "takeover", "config", "disclosure", "kev",
]

# nuclei grades several configuration weaknesses "info", which reads as a detection
# rather than a problem. These are the ones that are problems. Provenance policy, in
# one place, so the reasoning is reviewable.
SEVERITY_OVERRIDES = {
    "deprecated-tls": "medium",               # TLS 1.0/1.1 accepted
    "insecure-cipher-suite-detect": "medium",  # NULL/EXPORT/RC4/3DES-class suites
    "mismatched-ssl-certificate": "low",      # certificate does not name the host
    "obsolete-ssh-version": "medium",         # SSH protocol 1 / ancient server
    "ssh-sha1-hmac-algo": "low",
    "tftp-detect": "medium",                  # unauthenticated file transfer
    "ntp-enum-variables-enabled": "low",      # NTP mode 6 readvar answers anyone
    "snmpv3-detect": "info",
}

SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"]
_CVE_ID = re.compile(r"cve-\d{4}-\d{4,}", re.I)


def normalize_severity(template_id: str, sev: str) -> str:
    s = (sev or "").strip().lower()
    if template_id in SEVERITY_OVERRIDES:
        return SEVERITY_OVERRIDES[template_id]
    return s if s in SEVERITIES else "unknown"


# --- input validation ------------------------------------------------------------


def validate_target(raw: str) -> str:
    """Return a canonical IP literal, or raise ValueError.

    Only literals: a hostname would be resolved here, and the answer could differ from
    what the backend checked (DNS rebinding). The backend resolves names; this scans
    exactly the address it is given.
    """
    try:
        ip = ipaddress.ip_address((raw or "").strip())
    except ValueError:
        raise ValueError(f"not an IP address: {raw!r}")
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        raise ValueError(f"refusing to scan {ip}: loopback, unspecified, multicast or link-local")
    return str(ip)


def validate_cidr(raw: str) -> ipaddress._BaseNetwork:
    try:
        net = ipaddress.ip_network((raw or "").strip(), strict=False)
    except ValueError:
        raise ValueError(f"not a network: {raw!r}")
    if net.is_loopback or net.is_unspecified or net.is_multicast or net.is_link_local:
        raise ValueError(f"refusing to scan {net}: loopback, unspecified, multicast or link-local")
    if net.num_addresses > MAX_RANGE_ADDRESSES:
        raise ValueError(f"{net} is {net.num_addresses} addresses; the limit is {MAX_RANGE_ADDRESSES}")
    return net


def port_spec(tcp_ports) -> str:
    """'full' (the default) or a list of ports -> a naabu -p argument."""
    if tcp_ports in (None, "", "full"):
        return "1-65535"
    if not isinstance(tcp_ports, list) or not tcp_ports:
        raise ValueError("tcpPorts must be 'full' or a non-empty list of ports")
    out = set()
    for p in tcp_ports:
        if not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535:
            raise ValueError(f"invalid port: {p!r}")
        out.add(p)
    return ",".join(str(p) for p in sorted(out))


# --- command builders (pure, so they are testable without the tools) -------------


def naabu_cmd(target: str, ports: str, rate: int = PORT_RATE) -> list[str]:
    return [
        "naabu", "-host", target, "-p", ports,
        "-s", "c",          # connect scan: works unprivileged, never half-open
        "-Pn",              # the caller already knows the address is a host
        "-verify",          # re-confirm each open port with a full connect
        "-rate", str(rate), "-c", "25", "-retries", "2", "-timeout", "1000",
        "-json", "-silent", "-no-color", "-duc",
    ]


def update_cmd(staging: str) -> list[str]:
    """Download the templates into staging.

    No -duc here. -duc ("disable update check") also disables the template download
    this command exists to do: nuclei prints its banner, downloads nothing and exits
    0. The online update was shipped that way and never installed a template; the
    offline import, which the end-to-end test used, was unaffected.
    """
    return ["nuclei", "-update-templates", "-ud", staging]


def quick_cmd(target: str, rate: int = PORT_RATE) -> list[str]:
    """The 100 most common ports, briefly: is anything there at all?"""
    return [
        "naabu", "-host", target, "-top-ports", "100", "-s", "c", "-Pn",
        "-rate", str(rate), "-c", "25", "-retries", "1", "-timeout", "800",
        "-json", "-silent", "-no-color", "-duc",
    ]


def discover_cmd(cidr: str, rate: int = PORT_RATE) -> list[str]:
    # A range is found with the common ports, then each live address gets the full
    # sweep through /scan. 65535 ports times 1024 addresses would take most of a day.
    return [
        "naabu", "-host", cidr, "-top-ports", "1000", "-s", "c", "-Pn",
        "-rate", str(rate), "-c", "50", "-retries", "1", "-timeout", "800",
        "-json", "-silent", "-no-color", "-duc",
    ]


def fingerprintx_cmd(list_file: str) -> list[str]:
    return ["fingerprintx", "--json", "-w", "3000", "-l", list_file]


def nuclei_cmd(list_file: str, templates_dir: str, mode: str, excluded_templates: list[str],
               rate: int = NUCLEI_RATE, tags: list[str] | None = None) -> list[str]:
    """One nuclei pass. mode is 'tcp', 'ssl', 'http-tech', 'http-generic' or 'udp'.

    tags narrows a tcp pass to one identified service's templates."""
    base = [
        "nuclei", "-l", list_file, "-jsonl", "-silent", "-no-color", "-duc",
        "-ni",              # no out-of-band callbacks to a third-party server
        "-omit-raw",
        "-rl", str(rate), "-c", "25", "-bs", "25",
        "-timeout", "5" if mode in ("tcp", "ssl") else "10", "-retries", "1",
        "-H", f"User-Agent: {USER_AGENT}",
        "-etags", ",".join(EXCLUDED_TAGS),
        "-ept", ",".join(EXCLUDED_PROTOCOLS),
    ]
    excl = [os.path.join(templates_dir, d) for d in EXCLUDED_DIRS] + list(excluded_templates)
    if mode == "tcp":
        sel = ["-t", templates_dir, "-pt", "tcp,javascript",
               "-et", os.path.join(templates_dir, "javascript", "udp")]
        if tags:
            sel += ["-tags", ",".join(tags)]
    elif mode == "ssl":
        sel = ["-t", templates_dir, "-pt", "ssl"]
    elif mode == "http-tech":
        sel = ["-t", templates_dir, "-pt", "http", "-as"]
    elif mode == "http-generic":
        # Only templates that can produce a FINDING. 43% of this set is info-level
        # (1,580 of the 1,629 panel templates alone) -- product detections that the
        # http-tech pass already makes -- and on the test target they were most of
        # a 167-second pass that found nothing more.
        sel = ["-t", templates_dir, "-pt", "http", "-tags", ",".join(HTTP_GENERIC_TAGS),
               "-severity", "low,medium,high,critical,unknown"]
    elif mode == "udp":
        sel = ["-t", os.path.join(templates_dir, "javascript", "udp")]
    else:
        raise ValueError(f"unknown nuclei mode {mode!r}")
    for e in excl:
        sel += ["-et", e]
    return base + sel


# fingerprintx protocol names -> the template tags that cover them, where they
# differ. Anything not listed is looked up by its own name.
SERVICE_TAGS = {
    "postgresql": ["postgresql", "postgres"],
    "oracledb": ["oracle"],
    "imap": ["imap", "mail"],
    "pop3": ["pop3", "mail"],
    "smtp": ["smtp", "mail"],
    "mssql": ["mssql"],
    "ldap": ["ldap"],
    "rdp": ["rdp"],
    "smb": ["smb"],
}


def network_plan(target: str, services: dict[int, dict]) -> list[tuple[str, list[str], list[str] | None]]:
    """The non-HTTP nuclei passes for one address: (mode, targets, tags).

    Every template against every port was 330s for three ports on the test target:
    SSH checks waiting out timeouts on a Redis port, and so on. Instead each
    identified service gets the templates tagged for it; TLS ports get the TLS
    checks; ports fingerprintx could not identify still get everything, because an
    unidentified service is exactly where a blind check earns its keep. HTTP ports
    are left to the HTTP passes.
    """
    by_service: dict[str, list[str]] = {}
    unknown: list[str] = []
    tls: list[str] = []
    for port, s in sorted(services.items()):
        hp = hostport(target, port)
        svc = (s.get("service") or "").lower()
        if s.get("tls") or svc == "https":
            tls.append(hp)
        if svc in ("http", "https"):
            continue
        if svc:
            by_service.setdefault(svc, []).append(hp)
        else:
            unknown.append(hp)
    plan: list[tuple[str, list[str], list[str] | None]] = []
    for svc, targets in sorted(by_service.items()):
        plan.append(("tcp", targets, SERVICE_TAGS.get(svc, [svc])))
    if unknown:
        plan.append(("tcp", unknown, None))
    if tls:
        plan.append(("ssl", tls, None))
    return plan


# --- output parsers --------------------------------------------------------------


def _json_lines(text: str):
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            yield json.loads(line)
        except ValueError:
            continue


def parse_naabu(text: str) -> list[int]:
    """Open TCP ports. naabu repeats a port when it re-verifies it, so dedupe."""
    ports = set()
    for d in _json_lines(text):
        p = d.get("port")
        if isinstance(p, dict):  # older naabu nests {"Port": n}
            p = p.get("Port")
        try:
            p = int(p)
        except (TypeError, ValueError):
            continue
        if 1 <= p <= 65535 and (d.get("protocol") or "tcp") == "tcp":
            ports.add(p)
    return sorted(ports)


def parse_discover(text: str) -> list[str]:
    ips = set()
    for d in _json_lines(text):
        ip = d.get("ip") or d.get("host")
        if ip:
            ips.add(ip)
    return sorted(ips, key=lambda s: ipaddress.ip_address(s))


def parse_fingerprintx(text: str) -> dict[int, dict]:
    out = {}
    for d in _json_lines(text):
        try:
            port = int(d.get("port"))
        except (TypeError, ValueError):
            continue
        meta = d.get("metadata") or {}
        techs = meta.get("technologies") or []
        product = ""
        if techs and isinstance(techs, list):
            product = str(techs[0])
        out[port] = {
            "port": port,
            "proto": (d.get("transport") or "tcp").lower(),
            "service": (d.get("protocol") or "").lower(),
            "product": product,
            "version": str(d.get("version") or "")[:200],
            "tls": bool(d.get("tls")),
            "cpes": [c for c in (meta.get("cpes") or []) if isinstance(c, str)][:10],
        }
    return out


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v] if v else []
    if isinstance(v, list):
        return [str(x) for x in v if x]
    return []


def _port_of(d: dict) -> int:
    p = d.get("port")
    try:
        return int(p)
    except (TypeError, ValueError):
        pass
    m = re.search(r":(\d+)(?:/|$)", d.get("matched-at") or d.get("url") or "")
    return int(m.group(1)) if m else 0


def parse_nuclei(text: str) -> tuple[list[dict], list[dict]]:
    """nuclei JSONL -> (findings, detections).

    Anything graded info after the overrides is a detection -- a fact about the
    service ("this is Grafana"), not a problem with it -- and is reported separately
    so the findings list stays a list of things to fix.
    """
    findings, detections = [], []
    seen = set()
    for d in _json_lines(text):
        tid = d.get("template-id") or ""
        if not tid:
            continue
        info = d.get("info") or {}
        cls = info.get("classification") or {}
        port = _port_of(d)
        matched = d.get("matched-at") or d.get("host") or ""
        key = (tid, port, matched)
        if key in seen:
            continue
        seen.add(key)
        sev = normalize_severity(tid, info.get("severity"))
        cves = [c.upper() for c in _as_list(cls.get("cve-id"))]
        # Many CVE templates (the JavaScript ones especially) name the CVE only in
        # their id. Without it here the finding cannot be corroborated against the
        # package scan, which is the whole point of carrying CVEs at all.
        if not cves and _CVE_ID.fullmatch(tid):
            cves = [tid.upper()]
        item = {
            "templateId": tid,
            "name": str(info.get("name") or tid)[:300],
            "severity": sev,
            "port": port,
            "proto": "udp" if (d.get("template") or "").startswith("javascript/udp/") else "tcp",
            "matchedAt": str(matched)[:500],
            "cves": cves,
            "cwes": [c.upper() for c in _as_list(cls.get("cwe-id"))],
            "cvss": float(cls.get("cvss-score") or 0),
            "cvssVector": str(cls.get("cvss-metrics") or ""),
            "description": str(info.get("description") or "").strip()[:2000],
            "remediation": str(info.get("remediation") or "").strip()[:2000],
            "references": _as_list(info.get("reference"))[:10],
            "extracted": [str(x)[:300] for x in _as_list(d.get("extracted-results"))][:10],
            "tags": _as_list(info.get("tags"))[:20],
        }
        (detections if sev == "info" else findings).append(item)
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (rank.get(f["severity"], 9), -f["cvss"], f["port"], f["templateId"]))
    return findings, detections


def http_targets(target: str, services: dict[int, dict]) -> list[str]:
    """URLs for the ports fingerprintx identified as HTTP(S)."""
    host = f"[{target}]" if ":" in target else target
    out = []
    for port, s in sorted(services.items()):
        if s.get("service") in ("http", "https"):
            scheme = "https" if s.get("tls") or s.get("service") == "https" else "http"
            out.append(f"{scheme}://{host}:{port}")
    return out


def hostport(target: str, port: int) -> str:
    return f"[{target}]:{port}" if ":" in target else f"{target}:{port}"


# --- templates ---------------------------------------------------------------------

_META = ".prov-templates.json"
_excluded_cache: dict = {"key": None, "list": []}


def templates_present(d: str | None = None) -> bool:
    d = d or TEMPLATES_DIR
    return os.path.isdir(os.path.join(d, "http")) or os.path.isdir(os.path.join(d, "javascript"))


def credential_templates(d: str | None = None) -> list[str]:
    """Templates that iterate a credential wordlist, found by reading them. Cached on
    the directory's metadata file, which every update and import rewrites."""
    d = d or TEMPLATES_DIR
    meta = os.path.join(d, _META)
    try:
        key = os.stat(meta).st_mtime_ns
    except OSError:
        key = None
    if key is not None and _excluded_cache["key"] == key:
        return _excluded_cache["list"]
    found = []
    for root, _dirs, files in os.walk(d):
        for fn in files:
            if not fn.endswith(".yaml"):
                continue
            p = os.path.join(root, fn)
            try:
                with open(p, "r", errors="replace") as f:
                    if _CRED_WORDLIST.search(f.read()):
                        found.append(p)
            except OSError:
                continue
    _excluded_cache.update(key=key, list=sorted(found))
    return _excluded_cache["list"]


def read_templates_meta(d: str | None = None) -> dict:
    d = d or TEMPLATES_DIR
    try:
        with open(os.path.join(d, _META)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def write_templates_meta(d: str, version: str, source: str) -> None:
    with open(os.path.join(d, _META), "w") as f:
        json.dump({"version": version, "source": source,
                   "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, f)


def _nuclei_config_version() -> str:
    home = os.path.expanduser("~")
    for p in (os.path.join(home, ".config", "nuclei", ".templates-config.json"),
              os.path.join(home, "Library", "Application Support", "nuclei", ".templates-config.json")):
        try:
            with open(p) as f:
                return json.load(f).get("nuclei-templates-version", "")
        except (OSError, ValueError):
            continue
    return ""


def safe_extract(tf: tarfile.TarFile, dest: str) -> None:
    """Extract only regular files and directories that stay inside dest."""
    root = os.path.realpath(dest)
    for m in tf.getmembers():
        if not (m.isfile() or m.isdir()):
            raise ValueError(f"archive contains a link or special file: {m.name}")
        target = os.path.realpath(os.path.join(dest, m.name))
        if target != root and not target.startswith(root + os.sep):
            raise ValueError(f"archive member escapes the destination: {m.name}")
    tf.extractall(dest, filter="data")


def _find_templates_root(d: str) -> str:
    """An archive may hold the templates at its top level or inside one directory."""
    if templates_present(d):
        return d
    entries = [e for e in os.listdir(d) if not e.startswith(".")]
    if len(entries) == 1 and templates_present(os.path.join(d, entries[0])):
        return os.path.join(d, entries[0])
    raise ValueError("archive does not contain nuclei templates (no http/ or javascript/ directory)")


def pin_nuclei_config(templates_dir: str = TEMPLATES_DIR) -> None:
    """Point nuclei's own config at TEMPLATES_DIR.

    `nuclei -update-templates -ud <staging>` records the staging directory as THE
    templates directory, and staging is deleted once its contents are moved into
    place. A nuclei that starts and finds its configured directory missing tries to
    install templates from the internet -- which on an air-gapped deployment is a
    scan that hangs on a download before it checks anything.
    """
    d = os.path.join(os.path.expanduser("~"), ".config", "nuclei")
    p = os.path.join(d, ".templates-config.json")
    try:
        with open(p) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        cfg = {}
    cfg["nuclei-templates-directory"] = templates_dir
    try:
        os.makedirs(d, exist_ok=True)
        with open(p, "w") as f:
            json.dump(cfg, f)
    except OSError:
        pass


def _swap_in(new_root: str, version: str, source: str) -> None:
    """Replace TEMPLATES_DIR's contents. The directory itself is a volume mount point
    and cannot be renamed, so its children are replaced instead."""
    write_templates_meta(new_root, version, source)
    os.makedirs(TEMPLATES_DIR, exist_ok=True)
    for e in os.listdir(TEMPLATES_DIR):
        p = os.path.join(TEMPLATES_DIR, e)
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p, ignore_errors=True)
        else:
            try:
                os.remove(p)
            except OSError:
                pass
    for e in os.listdir(new_root):
        shutil.move(os.path.join(new_root, e), os.path.join(TEMPLATES_DIR, e))
    _excluded_cache.update(key=None, list=[])
    pin_nuclei_config()


# --- execution ---------------------------------------------------------------------


async def _run(args: list[str], timeout: float) -> subprocess.CompletedProcess:
    return await asyncio.to_thread(
        subprocess.run, args, capture_output=True, timeout=max(5, timeout))


def _remaining(deadline: float) -> float:
    return deadline - time.monotonic()


def alive(target: str, ports: list[int], timeout: float = 3.0) -> tuple[bool, str]:
    """Whether the address answers at all, for a target with no open ports.

    A refused connection is an answer: the host is there and nothing listens. A
    timeout on every probe is not -- and must not be reported as "no open ports",
    which reads as clean.
    """
    for p in ports:
        try:
            with socket.create_connection((target, p), timeout=timeout):
                return True, f"port {p} accepted a connection"
        except ConnectionRefusedError:
            return True, f"port {p} refused (host is up)"
        except OSError:
            continue
    if not ports:
        return False, "no open ports found and no probe ports to confirm the host is up"
    return False, ("no response on any port: the address is unreachable from the scanner, "
                   "or a firewall drops everything")


async def scan_target(body: dict) -> dict:
    target = validate_target(body.get("target", ""))
    ports = port_spec(body.get("tcpPorts", "full"))
    want_udp = bool(body.get("udp"))
    probe_ports = [p for p in (body.get("aliveProbePorts") or [22, 80, 443, 3389, 5985, 5986])
                   if isinstance(p, int) and 1 <= p <= 65535][:10]
    if not templates_present():
        raise RuntimeError("no nuclei templates installed: update or import them first")

    started = time.monotonic()
    deadline = started + SCAN_TIMEOUT
    tmp = tempfile.mkdtemp(prefix="prov-netscan-")
    try:
        phases: dict[str, float] = {}

        # Silent addresses first. A full sweep of an address that answers nothing --
        # an overlay peer whose tunnel is down, a host that is off -- waits out every
        # one of 65,535 connects: 584s on the test fabric, for a result of
        # "unreachable". If the host neither accepts nor refuses on its own known
        # ports or the 100 most common ones, it is reported unreachable now, saying
        # exactly what was tried.
        t0 = time.monotonic()
        up, why = await asyncio.to_thread(alive, target, probe_ports)
        if not up:
            qb = await _run(quick_cmd(target), min(_remaining(deadline), 120))
            if not parse_naabu(qb.stdout.decode(errors="replace")):
                phases["liveness"] = round(time.monotonic() - t0, 1)
                return {
                    "target": target, "reachable": False,
                    "reason": (f"no response on the host's own ports ({', '.join(map(str, probe_ports))}) or the "
                               "100 most common ports: unreachable from the scanner, or a firewall drops "
                               "everything. The full port sweep was skipped."),
                    "openPorts": [], "services": [], "findings": [], "detections": [],
                    "templates": read_templates_meta(), "errors": [], "phases": phases,
                    "durationSec": round(time.monotonic() - started, 1),
                }
        phases["liveness"] = round(time.monotonic() - t0, 1)

        t0 = time.monotonic()
        nb = await _run(naabu_cmd(target, ports), _remaining(deadline))
        open_ports = parse_naabu(nb.stdout.decode(errors="replace"))
        phases["ports"] = round(time.monotonic() - t0, 1)

        result = {
            "target": target, "reachable": True, "reason": "",
            "openPorts": open_ports, "services": [], "findings": [], "detections": [],
            "templates": read_templates_meta(), "errors": [], "phases": phases,
        }
        if not open_ports:
            up, why = await asyncio.to_thread(alive, target, probe_ports)
            result["reachable"], result["reason"] = up, why
            if not up:
                result["durationSec"] = round(time.monotonic() - started, 1)
                return result

        services: dict[int, dict] = {}
        if open_ports:
            lst = os.path.join(tmp, "ports.txt")
            with open(lst, "w") as f:
                f.write("\n".join(hostport(target, p) for p in open_ports))
            t0 = time.monotonic()
            fx = await _run(fingerprintx_cmd(lst), min(_remaining(deadline), 300))
            phases["fingerprint"] = round(time.monotonic() - t0, 1)
            services = parse_fingerprintx(fx.stdout.decode(errors="replace"))
            for p in open_ports:
                services.setdefault(p, {"port": p, "proto": "tcp", "service": "", "product": "",
                                        "version": "", "tls": False, "cpes": []})

        excluded = credential_templates()
        passes: list[tuple[str, list[str], list[str] | None]] = []
        if open_ports:
            passes += network_plan(target, services)
            urls = http_targets(target, services)
            if urls:
                passes.append(("http-tech", urls, None))
                passes.append(("http-generic", urls, None))
        if want_udp:
            passes.append(("udp", [target], None))

        findings, detections = [], []
        for i, (mode, targets, tags) in enumerate(passes):
            label = f"{mode}:{'+'.join(tags)}" if tags else mode
            if _remaining(deadline) < 10:
                result["errors"].append(f"time limit reached before the {label} pass")
                break
            lst = os.path.join(tmp, f"pass{i}.txt")
            with open(lst, "w") as f:
                f.write("\n".join(targets))
            t0 = time.monotonic()
            try:
                nu = await _run(nuclei_cmd(lst, TEMPLATES_DIR, mode, excluded, tags=tags), _remaining(deadline))
                phases[label] = round(time.monotonic() - t0, 1)
            except subprocess.TimeoutExpired:
                result["errors"].append(f"{label} pass timed out")
                break
            f_, d_ = parse_nuclei(nu.stdout.decode(errors="replace"))
            findings += f_
            detections += d_
            if nu.returncode != 0 and not f_ and not d_:
                result["errors"].append(f"{label} pass: " + nu.stderr.decode(errors="replace")[-300:])

        if want_udp:
            t0 = time.monotonic()
            for f_ in await asyncio.to_thread(probes.run_udp_probes, target):
                findings.append(f_)
            phases["udp-probes"] = round(time.monotonic() - t0, 1)

        result["services"] = [services[p] for p in sorted(services)]
        rank = {s: i for i, s in enumerate(SEVERITIES)}
        findings.sort(key=lambda f: (rank.get(f["severity"], 9), -f["cvss"], f["port"], f["templateId"]))
        result["findings"] = findings
        result["detections"] = detections
        result["durationSec"] = round(time.monotonic() - started, 1)
        return result
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- overlay route -------------------------------------------------------------------


def _route_dev(addr: str) -> tuple[str, str]:
    """(route type, device) the kernel would use for addr."""
    out = subprocess.run(["ip", "-j", "route", "get", addr], capture_output=True, timeout=5)
    routes = json.loads(out.stdout or b"[]")
    if not routes:
        return "", ""
    return routes[0].get("type", "unicast") or "unicast", routes[0].get("dev", "") or ""


def overlay_status() -> str:
    """'ok', 'no-route' or 'not-configured'.

    Asks the kernel which device it would use to reach an address on each overlay.
    Through the jump host's namespace that is a tunnel interface; anywhere else it is
    the default route, which cannot reach the overlay at all.

    The address probed must not be the jump host's OWN overlay address: that one is
    local (dev lo), and probing it -- as the first version did, with the subnet's
    first host, which is where the jump host sits by default -- reported every
    working deployment as having no route. So candidates that resolve as local are
    skipped. One routable overlay is enough; a deployment need not run both
    WireGuard and OpenVPN.
    """
    cidrs = [c.strip() for c in OVERLAY_CIDR.split(",") if c.strip()]
    if not cidrs:
        return "not-configured"
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        hosts = list(itertools.islice(net.hosts(), 2))
        candidates = hosts + [net.broadcast_address - 1] if net.num_addresses > 4 else hosts
        for probe in candidates:
            try:
                rtype, dev = _route_dev(str(probe))
            except Exception:  # noqa: BLE001 -- any failure means "cannot confirm this route"
                continue
            if rtype == "local":
                continue
            if dev.startswith(("wg", "tun")):
                return "ok"
            break  # a non-local answer that is not a tunnel: this overlay is not routable here
    return "no-route"


# --- HTTP ----------------------------------------------------------------------------


@app.middleware("http")
async def require_token(request: Request, call_next):
    if request.url.path == "/healthz":
        return await call_next(request)
    if not TOKEN:
        if ALLOW_NO_TOKEN:
            return await call_next(request)
        return JSONResponse({"error": "NETSCAN_TOKEN is not configured"}, status_code=503)
    got = request.headers.get("x-netscan-token", "")
    if not hmac.compare_digest(got.encode(), TOKEN.encode()):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return await call_next(request)


@app.get("/healthz")
def healthz():
    ov = overlay_status()
    ok = not (REQUIRE_OVERLAY and ov != "ok")
    return JSONResponse({"ok": ok, "overlay": ov, "templates": templates_present()},
                        status_code=200 if ok else 503)


@app.post("/scan")
async def scan(request: Request):
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    try:
        validate_target(body.get("target", ""))
        port_spec(body.get("tcpPorts", "full"))
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    async with _scan_sem:
        try:
            return JSONResponse(await scan_target(body))
        except RuntimeError as e:
            return JSONResponse({"error": str(e)}, status_code=409)
        except subprocess.TimeoutExpired:
            return JSONResponse({"error": "scan timed out"}, status_code=504)


@app.post("/discover")
async def discover(request: Request):
    try:
        body = await request.json()
        net = validate_cidr(body.get("cidr", ""))
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    async with _scan_sem:
        try:
            out = await _run(discover_cmd(str(net)), SCAN_TIMEOUT)
        except subprocess.TimeoutExpired:
            return JSONResponse({"error": "discovery timed out"}, status_code=504)
    return JSONResponse({"cidr": str(net), "addresses": parse_discover(out.stdout.decode(errors="replace"))})


@app.get("/templates/status")
def templates_status():
    meta = read_templates_meta()
    return JSONResponse({"present": templates_present(), **meta,
                         "excludedCredentialTemplates": len(credential_templates()) if templates_present() else 0})


@app.post("/templates/update")
def templates_update():
    with _templates_lock:
        staging = tempfile.mkdtemp(prefix="prov-templates-")
        try:
            proc = subprocess.run(update_cmd(staging), capture_output=True, timeout=TEMPLATES_TIMEOUT)
            output = (proc.stdout + proc.stderr).decode(errors="replace")[-4000:]
            if proc.returncode != 0 or not templates_present(staging):
                return JSONResponse({"ok": False, "output": output}, status_code=502)
            _swap_in(staging, _nuclei_config_version() or "unknown", "online")
            return JSONResponse({"ok": True, "output": output, **read_templates_meta()})
        except subprocess.TimeoutExpired:
            return JSONResponse({"ok": False, "error": "template update timed out"}, status_code=504)
        finally:
            shutil.rmtree(staging, ignore_errors=True)


@app.post("/templates/import")
async def templates_import(request: Request):
    body = await request.body()
    if not body:
        return JSONResponse({"ok": False, "error": "empty archive"}, status_code=400)
    if len(body) > MAX_TEMPLATES_UPLOAD:
        return JSONResponse({"ok": False, "error": "archive too large"}, status_code=413)
    version = request.headers.get("x-templates-version", "") or "imported"
    with _templates_lock:
        staging = tempfile.mkdtemp(prefix="prov-templates-")
        try:
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:*") as tf:
                safe_extract(tf, staging)
            root = _find_templates_root(staging)
            _swap_in(root, version, "import")
            return JSONResponse({"ok": True, **read_templates_meta()})
        except (tarfile.TarError, ValueError, OSError) as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
