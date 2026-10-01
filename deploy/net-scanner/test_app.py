"""Tests for the net-scanner sidecar.

Run: make netscan-test  (or: python -m pytest deploy/net-scanner)

The endpoints shell out to naabu, fingerprintx and nuclei, which is an integration
concern. What is covered here is what silently returns the wrong thing -- the
parsers, fed real output captured from the tools -- and the safety policy, which
must hold for every pass whatever else changes.
"""

import io
import os
import socket
import tarfile

import pytest
from fastapi.testclient import TestClient

import app as appmod
import probes
from app import (
    http_targets, network_plan, nuclei_cmd, parse_discover, parse_fingerprintx, parse_naabu,
    parse_nuclei, port_spec, safe_extract, validate_cidr, validate_target,
)

# Captured from naabu 2.6.1 with -verify: the port appears once per confirmation.
NAABU = """{"ip":"127.0.0.1","timestamp":"2026-09-30T23:44:42.111278Z","port":8099,"protocol":"tcp","tls":false}
{"ip":"127.0.0.1","timestamp":"2026-09-30T23:44:44.112605Z","port":8099,"protocol":"tcp","tls":false}
{"ip":"127.0.0.1","timestamp":"2026-09-30T23:44:44.2Z","port":22,"protocol":"tcp","tls":false}
"""

# Captured from fingerprintx 1.1.19 against python -m http.server.
FINGERPRINTX = """{"ip":"127.0.0.1","port":8099,"protocol":"http","tls":false,"transport":"tcp","version":"SimpleHTTP/0.6 Python/3.14.7","metadata":{"status":"200 OK","statusCode":200,"technologies":["SimpleHTTP:0.6","Python:3.14.7"],"cpes":["cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"]}}
"""

# Captured from nuclei 3.11.1 (trimmed of curl-command and template-path).
NUCLEI_GIT = """{"template":"http/exposures/configs/git-config.yaml","template-id":"git-config","info":{"name":"Git Configuration - Detect","tags":["config","git","exposure","vuln"],"description":"Git configuration was detected.","severity":"medium","classification":{"cve-id":null,"cwe-id":["cwe-200"],"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","cvss-score":5.3}},"type":"http","host":"127.0.0.1","port":"8099","scheme":"http","url":"http://127.0.0.1:8099","matched-at":"http://127.0.0.1:8099/.git/config","ip":"127.0.0.1","matcher-status":true}
"""


def test_naabu_dedupes_reverified_ports():
    assert parse_naabu(NAABU) == [22, 8099]


def test_naabu_ignores_noise_lines():
    assert parse_naabu("[INF] something\nnot json\n" + NAABU) == [22, 8099]


def test_discover_sorts_addresses_numerically():
    text = '{"ip":"10.0.0.10","port":22}\n{"ip":"10.0.0.9","port":80}\n{"ip":"10.0.0.10","port":80}\n'
    assert parse_discover(text) == ["10.0.0.9", "10.0.0.10"]


def test_fingerprintx_service():
    s = parse_fingerprintx(FINGERPRINTX)[8099]
    assert s["service"] == "http"
    assert s["product"] == "SimpleHTTP:0.6"
    assert s["version"].startswith("SimpleHTTP/0.6")
    assert s["tls"] is False
    assert s["cpes"] == ["cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"]


def test_nuclei_finding_fields():
    findings, detections = parse_nuclei(NUCLEI_GIT)
    assert detections == []
    f = findings[0]
    assert f["templateId"] == "git-config"
    assert f["severity"] == "medium"
    assert f["port"] == 8099
    assert f["cves"] == []          # a null cve-id is "none", not ["None"]
    assert f["cwes"] == ["CWE-200"]
    assert f["cvss"] == 5.3


def _nuclei_line(tid, sev, port="443", template=None, cve=None):
    import json
    return json.dumps({
        "template": template or f"ssl/{tid}.yaml", "template-id": tid,
        "info": {"name": tid, "severity": sev, "classification": {"cve-id": cve}},
        "host": "10.0.0.5", "port": port, "matched-at": f"10.0.0.5:{port}",
    })


# nuclei grades accepting TLS 1.0/1.1 "info". Left alone, the single most common
# network weakness would be filed as a detection and never appear as a finding.
def test_deprecated_tls_is_promoted_to_a_finding():
    findings, detections = parse_nuclei(_nuclei_line("deprecated-tls", "info"))
    assert [f["templateId"] for f in findings] == ["deprecated-tls"]
    assert findings[0]["severity"] == "medium"
    assert detections == []


def test_plain_info_is_a_detection_not_a_finding():
    findings, detections = parse_nuclei(_nuclei_line("tech-detect", "info", port="80"))
    assert findings == []
    assert detections[0]["templateId"] == "tech-detect"


def test_findings_sort_worst_first_and_cves_upper():
    text = "\n".join([
        _nuclei_line("a-low", "low"),
        _nuclei_line("b-crit", "critical", cve=["cve-2024-1234"]),
        _nuclei_line("c-high", "high"),
    ])
    findings, _ = parse_nuclei(text)
    assert [f["templateId"] for f in findings] == ["b-crit", "c-high", "a-low"]
    assert findings[0]["cves"] == ["CVE-2024-1234"]


def test_udp_template_findings_are_tagged_udp():
    findings, _ = parse_nuclei(_nuclei_line(
        "snmpv1-community-detect-string", "high", port="161",
        template="javascript/udp/misconfiguration/snmpv1-community-detect-string.yaml"))
    assert findings[0]["proto"] == "udp"


def test_duplicate_matches_collapse():
    line = _nuclei_line("weak-cipher-suites", "low")
    findings, _ = parse_nuclei(line + "\n" + line)
    assert len(findings) == 1


# --- safety policy: must hold for EVERY pass -----------------------------------------

@pytest.mark.parametrize("mode,tags", [("tcp", None), ("tcp", ["redis"]), ("ssl", None),
                                       ("http-tech", None), ("http-generic", None), ("udp", None)])
def test_every_pass_carries_the_exclusions(mode, tags):
    cmd = nuclei_cmd("/tmp/list", "/t", mode, ["/t/x/creds.yaml"], tags=tags)
    etags = cmd[cmd.index("-etags") + 1].split(",")
    for tag in ("dos", "fuzz", "intrusive", "bruteforce", "default-login"):
        assert tag in etags, f"{mode} pass does not exclude {tag}"
    ept = cmd[cmd.index("-ept") + 1].split(",")
    for proto in ("code", "headless", "file"):
        assert proto in ept, f"{mode} pass does not exclude the {proto} protocol"
    assert "-ni" in cmd, f"{mode} pass would make out-of-band callbacks"
    excluded = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-et"]
    assert "/t/javascript/default-logins" in excluded
    assert "/t/x/creds.yaml" in excluded
    ua = cmd[cmd.index("-H") + 1]
    assert ua.startswith("User-Agent: Provenance-NetScan")


def test_tcp_pass_does_not_run_udp_templates():
    cmd = nuclei_cmd("/tmp/list", "/t", "tcp", [])
    excluded = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-et"]
    assert "/t/javascript/udp" in excluded


def test_unknown_mode_is_refused():
    with pytest.raises(ValueError):
        nuclei_cmd("/tmp/list", "/t", "everything", [])


def test_credential_wordlist_templates_are_found(tmp_path):
    (tmp_path / "http").mkdir()
    guess = tmp_path / "http" / "guess.yaml"
    guess.write_text("payloads:\n  username: helpers/wordlists/ssh-users.txt\n")
    plugin = tmp_path / "http" / "plugin.yaml"
    plugin.write_text("payloads:\n  name: helpers/wordlists/grafana-plugins.txt\n")
    appmod._excluded_cache.update(key=None, list=[])
    found = appmod.credential_templates(str(tmp_path))
    assert str(guess) in found
    assert str(plugin) not in found  # a wordlist of paths is not a credential guess


# --- input validation ----------------------------------------------------------------

@pytest.mark.parametrize("bad", ["127.0.0.1", "::1", "0.0.0.0", "169.254.1.1", "224.0.0.1",
                                 "fe80::1", "example.com", "", "10.0.0.0/24"])
def test_target_refusals(bad):
    with pytest.raises(ValueError):
        validate_target(bad)


def test_target_canonicalised():
    assert validate_target(" 10.0.2.5 ") == "10.0.2.5"


def test_cidr_size_cap():
    assert str(validate_cidr("10.0.2.0/24")) == "10.0.2.0/24"
    with pytest.raises(ValueError):
        validate_cidr("10.0.0.0/16")
    with pytest.raises(ValueError):
        validate_cidr("127.0.0.0/30")


def test_port_spec():
    assert port_spec("full") == "1-65535"
    assert port_spec(None) == "1-65535"
    assert port_spec([443, 22, 22]) == "22,443"
    for bad in ([], [0], [70000], ["22"], [True], "1-100"):
        with pytest.raises(ValueError):
            port_spec(bad)


def test_http_targets_uses_tls_and_brackets_ipv6():
    svcs = {443: {"service": "http", "tls": True}, 80: {"service": "http", "tls": False},
            22: {"service": "ssh", "tls": False}}
    assert http_targets("10.0.0.5", svcs) == ["http://10.0.0.5:80", "https://10.0.0.5:443"]
    assert http_targets("2001:db8::5", {80: {"service": "http"}}) == ["http://[2001:db8::5]:80"]


# --- reachability --------------------------------------------------------------------

def test_refused_connection_means_the_host_is_up():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens now: connecting is refused
    up, why = appmod.alive("127.0.0.1", [port], timeout=1)
    assert up and "refused" in why


def test_no_probe_ports_is_not_reported_as_up():
    up, why = appmod.alive("192.0.2.1", [], timeout=1)
    assert not up and "no open ports" in why


# --- templates archive ---------------------------------------------------------------

def _tar(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for m, data in members:
            tf.addfile(m, io.BytesIO(data) if data is not None else None)
    buf.seek(0)
    return tarfile.open(fileobj=buf, mode="r:gz")


def test_safe_extract_refuses_links(tmp_path):
    link = tarfile.TarInfo("templates/evil")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    with pytest.raises(ValueError):
        safe_extract(_tar([(link, None)]), str(tmp_path))


def test_safe_extract_refuses_traversal(tmp_path):
    m = tarfile.TarInfo("../outside.yaml")
    m.size = 1
    with pytest.raises(ValueError):
        safe_extract(_tar([(m, b"x")]), str(tmp_path))


def test_templates_root_found_inside_one_directory(tmp_path):
    os.makedirs(tmp_path / "nuclei-templates" / "http")
    assert appmod._find_templates_root(str(tmp_path)) == str(tmp_path / "nuclei-templates")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError):
        appmod._find_templates_root(str(empty))


# --- token ---------------------------------------------------------------------------

def test_token_required(monkeypatch):
    monkeypatch.setattr(appmod, "TOKEN", "s3cret")
    monkeypatch.setattr(appmod, "ALLOW_NO_TOKEN", False)
    c = TestClient(appmod.app)
    assert c.get("/templates/status").status_code == 401
    assert c.get("/templates/status", headers={"X-Netscan-Token": "wrong"}).status_code == 401
    assert c.post("/scan", json={"target": "127.0.0.1"},
                  headers={"X-Netscan-Token": "s3cret"}).status_code == 400  # past auth, refused target
    assert c.get("/healthz").status_code in (200, 503)  # never behind the token


def test_missing_token_refuses_instead_of_opening(monkeypatch):
    monkeypatch.setattr(appmod, "TOKEN", "")
    monkeypatch.setattr(appmod, "ALLOW_NO_TOKEN", False)
    c = TestClient(appmod.app)
    r = c.get("/templates/status")
    assert r.status_code == 503 and "NETSCAN_TOKEN" in r.json()["error"]


def test_healthz_fails_when_overlay_required_but_unroutable(monkeypatch):
    monkeypatch.setattr(appmod, "REQUIRE_OVERLAY", True)
    monkeypatch.setattr(appmod, "overlay_status", lambda: "no-route")
    r = TestClient(appmod.app).get("/healthz")
    assert r.status_code == 503 and r.json()["overlay"] == "no-route"


# --- UDP probes ----------------------------------------------------------------------

# A real Supermicro BMC's presence pong.
PONG = bytes.fromhex("0600ff06000011be40000010000011be00000000810000000000")


def test_rmcp_pong_recognised():
    assert probes.is_rmcp_pong(PONG)
    assert not probes.is_rmcp_pong(probes.RMCP_PING)  # our own ping is not a pong
    assert not probes.is_rmcp_pong(b"")


def test_ssdp_reply_recognised():
    reply = b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nSERVER: Linux UPnP/1.0 MiniUPnPd/2.1\r\n\r\n"
    assert probes.is_ssdp_reply(reply)
    assert not probes.is_ssdp_reply(b"HTTP/1.1 404 Not Found\r\n\r\n")


def test_udp_probes_report_what_answered():
    def exchange(target, port, payload, timeout=2.0):
        if port == 623:
            return PONG
        if port == 1900:
            return b"HTTP/1.1 200 OK\r\nST: ssdp:all\r\nSERVER: MiniUPnPd/2.1\r\n\r\n"
        return b""
    found = {f["templateId"]: f for f in probes.run_udp_probes("10.0.0.7", exchange=exchange)}
    assert found["prov-ipmi-exposed"]["severity"] == "high"
    assert found["prov-ipmi-exposed"]["cves"] == ["CVE-2013-4786"]
    assert found["prov-ssdp-exposed"]["extracted"] == ["MiniUPnPd/2.1"]


def test_udp_probes_silent_target_reports_nothing():
    assert probes.run_udp_probes("10.0.0.7", exchange=lambda *a, **k: b"") == []


# The JavaScript CVE templates carry the CVE only in their id; without picking it
# up there, those findings could never be corroborated against the package scan.
def test_cve_taken_from_template_id_when_classification_has_none():
    findings, _ = parse_nuclei(_nuclei_line("CVE-2025-49844", "critical", port="6379",
                                            template="javascript/cves/2025/CVE-2025-49844.yaml"))
    assert findings[0]["cves"] == ["CVE-2025-49844"]
    findings, _ = parse_nuclei(_nuclei_line("redis-lua-uaf", "critical", port="6379"))
    assert findings[0]["cves"] == []


# Each identified service gets only its own templates; unidentified ports get
# everything; TLS ports get the TLS checks; HTTP is left to the HTTP passes.
def test_network_plan_targets_templates_by_service():
    services = {
        22: {"service": "ssh", "tls": False},
        443: {"service": "https", "tls": True},
        80: {"service": "http", "tls": False},
        5432: {"service": "postgresql", "tls": False},
        6379: {"service": "redis", "tls": False},
        6380: {"service": "redis", "tls": True},
        9999: {"service": "", "tls": False},
    }
    plan = network_plan("10.0.0.5", services)
    assert ("tcp", ["10.0.0.5:5432"], ["postgresql", "postgres"]) in plan
    assert ("tcp", ["10.0.0.5:6379", "10.0.0.5:6380"], ["redis"]) in plan
    assert ("tcp", ["10.0.0.5:22"], ["ssh"]) in plan
    assert ("tcp", ["10.0.0.5:9999"], None) in plan          # unknown: the full set
    assert ("ssl", ["10.0.0.5:443", "10.0.0.5:6380"], None) in plan
    for mode, targets, _ in plan:
        assert "10.0.0.5:80" not in targets                  # HTTP has its own passes
        assert not (mode == "tcp" and "10.0.0.5:443" in targets)


def test_tagged_tcp_pass_narrows_by_tag():
    cmd = nuclei_cmd("/l", "/t", "tcp", [], tags=["postgresql", "postgres"])
    assert cmd[cmd.index("-tags") + 1] == "postgresql,postgres"
    assert "-tags" not in nuclei_cmd("/l", "/t", "tcp", [])


def test_generic_http_pass_skips_detection_only_templates():
    cmd = nuclei_cmd("/l", "/t", "http-generic", [])
    assert "info" not in cmd[cmd.index("-severity") + 1].split(",")
    # tech detection must keep info: it is what -as selects templates from
    assert "-severity" not in nuclei_cmd("/l", "/t", "http-tech", [])


# The jump host's own overlay address is local. Probing it -- the subnet's first
# host, where the jump host sits by default -- reported a working overlay as having
# no route, which marked the scanner unhealthy and every overlay scan unreachable.
# These are the kernel's real answers inside the jump host's namespace.
def _fake_routes(table):
    def get(addr):
        return table.get(addr, ("unicast", "eth0"))
    return get


def test_overlay_ok_when_first_host_is_the_jump_hosts_own_address(monkeypatch):
    monkeypatch.setattr(appmod, "OVERLAY_CIDR", "10.100.0.0/24,10.101.0.0/24")
    monkeypatch.setattr(appmod, "_route_dev", _fake_routes({
        "10.100.0.1": ("local", "lo"),
        "10.100.0.2": ("unicast", "wg0"),
    }))
    assert appmod.overlay_status() == "ok"


def test_overlay_no_route_from_outside_the_jump_host(monkeypatch):
    monkeypatch.setattr(appmod, "OVERLAY_CIDR", "10.100.0.0/24")
    monkeypatch.setattr(appmod, "_route_dev", _fake_routes({}))  # everything via eth0
    assert appmod.overlay_status() == "no-route"


def test_overlay_not_configured(monkeypatch):
    monkeypatch.setattr(appmod, "OVERLAY_CIDR", "")
    assert appmod.overlay_status() == "not-configured"


# A dark address must come back unreachable WITHOUT the 65,535-port sweep; one that
# answers only on an uncommon port must still get the sweep.
def _scan_with(monkeypatch, tmp_path, alive_up, quick_open):
    calls = []

    async def fake_run(args, timeout):
        calls.append(args)
        out = ""
        if "-top-ports" in args and "100" in args and quick_open:
            out = '{"ip":"10.0.0.9","port":%d,"protocol":"tcp"}' % quick_open
        import subprocess as sp
        return sp.CompletedProcess(args, 0, out.encode(), b"")

    (tmp_path / "http").mkdir()
    monkeypatch.setattr(appmod, "TEMPLATES_DIR", str(tmp_path))
    monkeypatch.setattr(appmod, "_run", fake_run)
    monkeypatch.setattr(appmod, "alive", lambda t, p, timeout=3.0: (alive_up, "probe"))
    import asyncio
    res = asyncio.run(appmod.scan_target({"target": "10.0.0.9", "tcpPorts": "full", "aliveProbePorts": [22]}))
    swept = any("-p" in c and "1-65535" in c for c in calls)
    return res, swept


def test_silent_address_skips_the_full_sweep(monkeypatch, tmp_path):
    res, swept = _scan_with(monkeypatch, tmp_path, alive_up=False, quick_open=None)
    assert res["reachable"] is False and "full port sweep was skipped" in res["reason"]
    assert not swept


def test_address_answering_only_on_a_common_port_is_still_swept(monkeypatch, tmp_path):
    res, swept = _scan_with(monkeypatch, tmp_path, alive_up=False, quick_open=8443)
    assert swept


def test_address_refusing_on_its_own_port_is_swept(monkeypatch, tmp_path):
    res, swept = _scan_with(monkeypatch, tmp_path, alive_up=True, quick_open=None)
    assert swept


def test_online_update_does_not_disable_itself():
    cmd = appmod.update_cmd("/tmp/staging")
    assert "-update-templates" in cmd and "-duc" not in cmd
    assert cmd[cmd.index("-ud") + 1] == "/tmp/staging"


# An update that exits 0 without installing anything must be reported as a failure,
# not swapped in over the working templates.
def test_update_that_installs_nothing_is_a_failure(monkeypatch, tmp_path):
    import subprocess as sp
    monkeypatch.setattr(appmod, "TOKEN", "t")
    monkeypatch.setattr(appmod, "TEMPLATES_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(appmod.subprocess, "run",
                        lambda *a, **k: sp.CompletedProcess(a, 0, b"banner only", b""))
    r = TestClient(appmod.app).post("/templates/update", headers={"X-Netscan-Token": "t"})
    assert r.status_code == 502 and r.json()["ok"] is False


def test_nuclei_rate_is_clamped(monkeypatch):
    monkeypatch.setattr(appmod, "NUCLEI_RATE", 100)
    monkeypatch.setattr(appmod, "NUCLEI_RATE_MAX", 500)
    assert appmod.nuclei_rate(None) == 100
    assert appmod.nuclei_rate(300) == 300
    assert appmod.nuclei_rate(10_000) == 500
    assert appmod.nuclei_rate(1) == 10
    for bad in ("300", -5, True, 2.5):
        with pytest.raises(ValueError):
            appmod.nuclei_rate(bad)
