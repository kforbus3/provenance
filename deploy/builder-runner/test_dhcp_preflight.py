"""The preflight has to refuse the configurations that take down a live network —
and accept the one this feature exists to create.

Standalone DHCP on the interface carrying the default route, or a lease range
inside a network this host is already on, puts a second DHCP server on somebody's
LAN. The symptoms land on machines that have nothing to do with imaging, and
nothing in this product's logs connects them to it. Both were missed: MODE=dhcp on
the LAN interface with a range inside the LAN's own subnet produced one complaint,
about the netboot imager not being built.

Then the check over-corrected. It looked at every interface INCLUDING the chosen
one, so a dedicated provisioning NIC at 192.168.50.1/24 handing out
192.168.50.100–150 — a DHCP server on the segment it serves, which is the only
correct arrangement there is — was refused as "a network this host is already on".
That was found by configuring it for real against an isolated Proxmox bridge.

Two reasons it was not caught earlier, both fixed here:

  * the test that named this case asserted only that the *default route*
    complaint was absent, which was never in question, so it could not fail for
    the property in its own name;
  * this file was written as pytest, while every other test beside it is a plain
    script, and it was not in the imaging-test target's list — so it had never
    run at all.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("PROJECT_DIR", "/project")

import orchestrator  # noqa: E402

failures = []
checks_run = 0


def check(name, cond):
    global checks_run
    checks_run += 1
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        failures.append(name)


LAN = {"name": "eth0", "ip": "10.10.0.224", "prefixlen": 24, "default": True, "up": True}
ISOLATED = {"name": "eth1", "ip": "192.168.50.1", "prefixlen": 24, "default": False, "up": True}


def problems_for(cfg, ifaces):
    """Run the check with list_interfaces replaced, and always put it back."""
    original = orchestrator.list_interfaces
    orchestrator.list_interfaces = lambda: ifaces
    try:
        return orchestrator._dhcp_collision_problems(cfg)
    finally:
        orchestrator.list_interfaces = original


print("== the configuration this feature is FOR is accepted ==")

# A dedicated NIC, an address of its own, and a range inside its own subnet. A
# DHCP server has to be on the segment it serves.
p = problems_for({
    "INTERFACE": "eth1", "MODE": "dhcp",
    "DHCP_RANGE_START": "192.168.50.64", "DHCP_RANGE_END": "192.168.50.200",
}, [LAN, ISOLATED])
check(f"an isolated segment serving its own subnet is allowed ({p})", p == [])

print("== the two configurations that take down a live network ==")

p = problems_for({
    "INTERFACE": "eth0", "MODE": "dhcp",
    "DHCP_RANGE_START": "172.31.5.10", "DHCP_RANGE_END": "172.31.5.50",
}, [LAN, ISOLATED])
check("standalone DHCP on the default-route interface is refused",
      any("default route" in x for x in p))

p = problems_for({
    "INTERFACE": "eth1", "MODE": "dhcp",
    "DHCP_RANGE_START": "10.10.0.100", "DHCP_RANGE_END": "10.10.0.200",
}, [LAN, ISOLATED])
check("a lease range inside the LAN is refused even from another NIC",
      any("already on" in x for x in p))

# Exactly what was configured on the QA host, which the preflight passed.
#
# One refusal, not two. This used to assert both, and the second one -- "that
# range is inside a network this host is already on" -- was the same sentence
# twice: the network in question IS the chosen interface's, and the chosen
# interface is the default-route one, which is already the first complaint. The
# range check now skips the chosen interface (it has to, or the correct
# configuration is refused), so what stops this is the default-route rule.
p = problems_for({
    "INTERFACE": "eth0", "MODE": "dhcp",
    "DHCP_RANGE_START": "10.10.0.100", "DHCP_RANGE_END": "10.10.0.200",
}, [LAN])
check(f"the real misconfiguration is still refused ({p})",
      len(p) >= 1 and any("default route" in x for x in p))

print("== a range the provisioning NIC is not on ==")

# The true version of the check that was over-broad: addresses this server cannot
# reach, handed to machines that then fail looking like a broken image.
p = problems_for({
    "INTERFACE": "eth1", "MODE": "dhcp",
    "DHCP_RANGE_START": "192.168.99.10", "DHCP_RANGE_END": "192.168.99.50",
}, [LAN, ISOLATED])
check("a range off the provisioning segment is refused",
      any("not on eth1" in x for x in p))

print("== the preflight runs on page render and must never throw ==")


def boom():
    raise OSError("no docker socket")


original = orchestrator.list_interfaces
orchestrator.list_interfaces = boom
try:
    p = orchestrator._dhcp_collision_problems({"INTERFACE": "eth0", "MODE": "dhcp"})
    check("unreadable interfaces produce no problems rather than an exception", p == [])
except Exception as e:  # noqa: BLE001
    check(f"unreadable interfaces raised {e!r}", False)
finally:
    orchestrator.list_interfaces = original

print(f"\n{checks_run - len(failures)} passed, {len(failures)} failed")
sys.exit(1 if failures else 0)
