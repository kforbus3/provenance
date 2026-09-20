"""The preflight has to refuse the two configurations that take down a live network.

Standalone DHCP on the interface carrying the default route, or a lease range inside a
network this host is already on, puts a second DHCP server on somebody's LAN. The
symptoms land on machines that have nothing to do with imaging, and nothing in this
product's logs connects them to it.

Both were missed: configuring MODE=dhcp on the LAN interface with a range inside the
LAN's own subnet produced one complaint, about the netboot imager not being built.
list_interfaces() had marked that interface as `default` all along, and its docstring
already said it is "the one you do *not* want a standalone DHCP server on".
"""

import orchestrator


LAN = {"name": "eth0", "ip": "10.10.0.224", "prefixlen": 24, "default": True, "up": True}
ISOLATED = {"name": "eth1", "ip": "192.168.50.1", "prefixlen": 24, "default": False, "up": True}


def _with_interfaces(monkeypatch, ifaces):
    monkeypatch.setattr(orchestrator, "list_interfaces", lambda: ifaces)


def test_refuses_dhcp_on_the_default_route_interface(monkeypatch):
    _with_interfaces(monkeypatch, [LAN, ISOLATED])
    problems = orchestrator._dhcp_collision_problems({
        "INTERFACE": "eth0", "MODE": "dhcp",
        "DHCP_RANGE_START": "172.31.5.10", "DHCP_RANGE_END": "172.31.5.50",
    })
    assert any("default route" in p for p in problems), (
        "standalone DHCP on the main LAN interface was allowed: %r" % problems)


def test_refuses_a_range_inside_a_network_this_host_is_on(monkeypatch):
    _with_interfaces(monkeypatch, [LAN, ISOLATED])
    problems = orchestrator._dhcp_collision_problems({
        "INTERFACE": "eth1", "MODE": "dhcp",
        "DHCP_RANGE_START": "10.10.0.100", "DHCP_RANGE_END": "10.10.0.200",
    })
    assert any("already on" in p for p in problems), (
        "a lease range inside the LAN was allowed: %r" % problems)


def test_the_real_misconfiguration_is_refused_on_both_counts(monkeypatch):
    # Exactly what was configured on the QA host, which the preflight passed.
    _with_interfaces(monkeypatch, [LAN])
    problems = orchestrator._dhcp_collision_problems({
        "INTERFACE": "eth0", "MODE": "dhcp",
        "DHCP_RANGE_START": "10.10.0.100", "DHCP_RANGE_END": "10.10.0.200",
    })
    assert len(problems) >= 2, "expected both refusals, got %r" % problems


def test_an_isolated_segment_with_its_own_range_is_allowed(monkeypatch):
    # The configuration this feature is FOR must not be refused.
    _with_interfaces(monkeypatch, [LAN, ISOLATED])
    problems = orchestrator._dhcp_collision_problems({
        "INTERFACE": "eth1", "MODE": "dhcp",
        "DHCP_RANGE_START": "192.168.50.64", "DHCP_RANGE_END": "192.168.50.200",
    })
    # eth1 IS on 192.168.50.0/24 — that is the provisioning segment this server owns,
    # and handing out addresses there is the entire point.
    assert not any("default route" in p for p in problems), problems


def test_preflight_never_throws_when_interfaces_cannot_be_read(monkeypatch):
    def boom():
        raise OSError("no docker socket")
    monkeypatch.setattr(orchestrator, "list_interfaces", boom)
    assert orchestrator._dhcp_collision_problems({"INTERFACE": "eth0", "MODE": "dhcp"}) == []
