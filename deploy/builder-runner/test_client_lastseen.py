"""The provisioning client list reported "last seen" as a log prefix.

server_clients took line[:19] as the timestamp. These containers print no time of
their own -- dnsmasq's lines start "dnsmasq-dhcp: 95640 DHCPACK(...)" -- so a
machine that had just PXE-booted was reported as

    {"mac":"bc:24:11:ce:a4:e2","ip":"192.168.50.100","event":"got boot info",
     "last":"dnsmasq-dhcp: 95640"}

which the UI shows as when it was last seen. Found by PXE-booting a machine on an
isolated segment and reading the answer.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("PROJECT_DIR", "/project")

import orchestrator  # noqa: E402

failures = []
checks = 0


def check(name, cond):
    global checks
    checks += 1
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        failures.append(name)


print("== the docker timestamp is read, and nothing else is mistaken for one ==")

real = ("2026-09-20T21:57:49.123456789Z dnsmasq-dhcp: 95640 "
        "DHCPACK(ens19) 192.168.50.100 bc:24:11:ce:a4:e2")
check("a nanosecond UTC stamp is read",
      orchestrator._log_time(real) == "2026-09-20 21:57:49")
check("an offset stamp is read",
      orchestrator._log_time("2026-09-20T21:57:49+00:00 dnsmasq-dhcp: 1 BOOTP")
      == "2026-09-20 21:57:49")

# The exact line that produced the bad value.
check("an untimestamped dnsmasq line yields nothing, not its own prefix",
      orchestrator._log_time("dnsmasq-dhcp: 95640 DHCPACK(ens19) 192.168.50.100") == "")
check("an empty line yields nothing", orchestrator._log_time("") == "")
check("a line that merely starts with digits yields nothing",
      orchestrator._log_time("12345 something happened") == "")

print("== and the log helper asks for timestamps when they are wanted ==")

seen = {}


def fake_run(cmd, **kw):
    seen["cmd"] = cmd

    class P:
        stdout = ""
        stderr = ""
    return P()


real_run = orchestrator.subprocess.run
orchestrator.subprocess.run = fake_run
try:
    orchestrator._docker_logs("c", 10, since="15m", timestamps=True)
    check("--timestamps is passed when asked for", "--timestamps" in seen["cmd"])
    orchestrator._docker_logs("c", 10, since="15m")
    check("and not otherwise", "--timestamps" not in seen["cmd"])
finally:
    orchestrator.subprocess.run = real_run

print(f"\n{checks - len(failures)} passed, {len(failures)} failed")
sys.exit(1 if failures else 0)
