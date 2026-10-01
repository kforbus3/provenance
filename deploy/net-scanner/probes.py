"""UDP probes for the two exposures nuclei has no template for.

Each sends one well-formed discovery packet and reads one reply. Neither
authenticates, guesses anything, or asks the target to do work beyond answering
"are you there" -- the same question the protocol's own discovery tools ask.

  IPMI / BMC (623/udp)  An RMCP presence ping. A reply means a baseboard
                        management controller is reachable: out-of-band control
                        of the machine, with the IPMI 2.0 RAKP design flaw
                        (CVE-2013-4786) that lets anyone fetch a password hash.
  SSDP (1900/udp)       A unicast M-SEARCH. A reply means UPnP discovery answers
                        off the local segment, which is a reflection/amplification
                        source and usually a sign of UPnP exposed where it should
                        not be.
"""

import socket

# ASF/RMCP presence ping: RMCP header (version 6, reserved, seq 0xff, class ASF)
# followed by the ASF IANA number 4542, type 0x80 (presence ping), tag, reserved,
# data length 0.
RMCP_PING = bytes.fromhex("0600ff06000011be80000000")

SSDP_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()


def is_rmcp_pong(data: bytes) -> bool:
    """An RMCP presence pong: RMCP v6 header, ASF class, message type 0x40."""
    return len(data) >= 12 and data[0] == 0x06 and (data[3] & 0x0F) == 0x06 and data[8] == 0x40


def is_ssdp_reply(data: bytes) -> bool:
    head = data[:200].upper()
    return head.startswith(b"HTTP/1.1 200") and (b"ST:" in data.upper() or b"USN:" in data.upper())


def _udp_exchange(target: str, port: int, payload: bytes, timeout: float = 2.0) -> bytes:
    fam = socket.AF_INET6 if ":" in target else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(payload, (target, port))
            data, _ = s.recvfrom(4096)
            return data
        except OSError:
            return b""


def _finding(tid, name, sev, port, desc, remediation, cves=(), cvss=0.0, extracted=()):
    return {
        "templateId": tid, "name": name, "severity": sev, "port": port, "proto": "udp",
        "matchedAt": "", "cves": list(cves), "cwes": [], "cvss": cvss, "cvssVector": "",
        "description": desc, "remediation": remediation, "references": [],
        "extracted": list(extracted), "tags": ["udp", "prov-probe"],
    }


def run_udp_probes(target: str, exchange=_udp_exchange) -> list[dict]:
    out = []
    if is_rmcp_pong(exchange(target, 623, RMCP_PING)):
        f = _finding(
            "prov-ipmi-exposed", "IPMI/BMC management interface reachable", "high", 623,
            "A baseboard management controller answered an RMCP presence ping. The BMC "
            "controls power, console and firmware independently of the operating system, "
            "and IPMI 2.0's RAKP authentication discloses a password hash to anyone who "
            "asks for it (CVE-2013-4786).",
            "Put BMC interfaces on a dedicated management network that hosts and users "
            "cannot reach, and disable IPMI-over-LAN where it is not needed.",
            cves=["CVE-2013-4786"], cvss=7.5)
        f["matchedAt"] = f"{target}:623"
        out.append(f)
    reply = exchange(target, 1900, SSDP_SEARCH)
    if is_ssdp_reply(reply):
        server = ""
        for line in reply.decode(errors="replace").splitlines():
            if line.upper().startswith("SERVER:"):
                server = line.split(":", 1)[1].strip()[:200]
        f = _finding(
            "prov-ssdp-exposed", "SSDP/UPnP answers unicast discovery", "medium", 1900,
            "The address answered an SSDP M-SEARCH sent directly to it. SSDP replies are "
            "larger than the request, which makes this a reflection and amplification "
            "source, and UPnP reachable beyond the local segment exposes device control.",
            "Disable UPnP/SSDP on the device, or block 1900/udp from untrusted networks.",
            extracted=[server] if server else [])
        f["matchedAt"] = f"{target}:1900"
        out.append(f)
    return out
