"""The preflight check's socket path, which is not where it used to be.

The runner talks to the daemon through the dockerproxy at /shared/docker.sock and
never holds the raw socket. preflight() tested a hard-coded /var/run/docker.sock,
so on a correctly deployed stack it reported a problem that was permanently
present and permanently untrue — and a preflight that always complains is one
people learn to scroll past, which is expensive when the other entries are the
reasons a machine cannot be imaged.
"""

import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("PROJECT_DIR", "/project")

failures = []


checks_run = 0


def check(name, cond):
    global checks_run
    checks_run += 1
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        failures.append(name)


def socket_path_with(docker_host):
    if docker_host is None:
        os.environ.pop("DOCKER_HOST", None)
    else:
        os.environ["DOCKER_HOST"] = docker_host
    import orchestrator
    importlib.reload(orchestrator)
    return orchestrator.docker_socket_path()


print("== the socket checked is the socket used ==")
check("the proxied socket is what gets checked",
      socket_path_with("unix:///shared/docker.sock") == "/shared/docker.sock")
check("an unset DOCKER_HOST falls back to the daemon default",
      socket_path_with(None) == "/var/run/docker.sock")
check("an empty DOCKER_HOST falls back too",
      socket_path_with("") == "/var/run/docker.sock")
check("a raw socket mount is still checked",
      socket_path_with("unix:///var/run/docker.sock") == "/var/run/docker.sock")

print("== a remote daemon has no local path to test ==")
check("tcp:// yields no path rather than a wrong one",
      socket_path_with("tcp://dockerd:2375") == "")
check("ssh:// yields no path either",
      socket_path_with("ssh://user@host") == "")
check("unix:// with nothing after it falls back",
      socket_path_with("unix://") == "/var/run/docker.sock")



import orchestrator as orch  # noqa: E402

print("== a duplicate server IP is a named problem, not a packet capture ==")
# The probe itself needs a raw socket and a live segment, so the wiring is what
# is pinned here: a claimant reported by the probe MUST surface as a preflight
# problem naming the MAC, and a clean probe must add nothing. The afternoon this
# encodes: an old provisioning server still held the address, every PXE boot
# died on a connection reset, and nothing in any log on this host said why.
_orig = orch.probe_duplicate_ip
orch.probe_duplicate_ip = lambda iface, ip: ["bc:24:11:3a:00:e7"]
_probs = orch.provisioning_preflight({"INTERFACE": "ens19", "SERVER_IP": "192.168.50.1",
                                      "MODE": "dhcp", "DHCP_RANGE_START": "192.168.50.100",
                                      "DHCP_RANGE_END": "192.168.50.200", "IMAGE_FILE": ""})
check("a claimant surfaces as a problem",
      any("bc:24:11:3a:00:e7" in p for p in _probs))
check("the problem says what to do about it",
      any("Power it off" in p for p in _probs))

orch.probe_duplicate_ip = lambda iface, ip: []
_probs = orch.provisioning_preflight({"INTERFACE": "ens19", "SERVER_IP": "192.168.50.1",
                                      "MODE": "dhcp", "DHCP_RANGE_START": "192.168.50.100",
                                      "DHCP_RANGE_END": "192.168.50.200", "IMAGE_FILE": ""})
check("a clean probe adds nothing", not any("answering for" in p for p in _probs))
orch.probe_duplicate_ip = _orig

print("== the inline ARP prober is valid python ==")
try:
    compile(orch._ARP_PROBE_PY, "<arp-probe>", "exec")
    check("compiles", True)
except SyntaxError as e:
    check(f"compiles ({e})", False)

print(f"\n{checks_run - len(failures)} passed, {len(failures)} failed")
sys.exit(1 if failures else 0)
