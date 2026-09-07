"""The open-file limit every build container and build script must be given.

The bug this pins, and it cost days: RHEL-family builds hung forever, always at
`Installing : glibc`, the first package in the bootstrap with a scriptlet. It was
not LUKS, not the loop device, not the CPU baseline, not dnf, and not the distro
release -- the identical transaction into a plain directory in a stock
rockylinux:9 container hung the same way, and it never reproduced on a laptop.

rpm closes every file descriptor from 3 up to the *soft* RLIMIT_NOFILE between
fork() and exec() of a scriptlet. Docker gives a container whatever the daemon
inherited, and a dockerd unit with LimitNOFILE=infinity means 1073741816 -- a
billion close() calls at 100% CPU, per scriptlet. The parent sits in wait4() and
the child never reaches exec(), so it still carries the parent's command line:
from the outside it looks like dnf itself is spinning, which is what sent the
first three investigations to the wrong place.

Two halves, and this checks both, because either alone leaves a hole:

  - build-image.sh caps it, so the script is correct however it is invoked --
    by hand, in CI, in a container someone started themselves.
  - the orchestrator caps it on the container, so every other thing in the
    build (the netboot imager, the bundle build) gets it too, including steps
    that never enter build-image.sh.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("PROJECT_DIR", "/project")

import orchestrator as orch  # noqa: E402

failures = []


def check(name, cond):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        failures.append(name)


# The number that matters. Anything at or below this is survivable; the failure
# mode is a soft limit in the hundreds of millions, so the test is "bounded",
# not "exactly 65536".
SANE_MAX = 1 << 20

print("== the orchestrator caps nofile on the container ==")
m = re.search(r"nofile=(\d+):(\d+)", orch.NOFILE_ULIMIT)
check("NOFILE_ULIMIT is a docker --ulimit nofile flag",
      "--ulimit" in orch.NOFILE_ULIMIT and m is not None)
if m:
    soft, hard = int(m.group(1)), int(m.group(2))
    # Soft is the one rpm reads. Hard being sane too keeps a build step that
    # raises its own soft limit from walking straight back into the bug.
    check(f"soft limit {soft} is bounded", 0 < soft <= SANE_MAX)
    check(f"hard limit {hard} is bounded", 0 < hard <= SANE_MAX)
    check("soft does not exceed hard", soft <= hard)
check("the flag is space-terminated so it cannot glue onto the next argument",
      orch.NOFILE_ULIMIT.endswith(" "))

print("== every build command carries it ==")
# Reach the command builders the way the API does. Each returns (argv, label)
# or (argv, label, env); the shell script is the last element of argv.
builders = [
    ("image build (deb)", lambda: orch.build_image_cmd(
        {"name": "t", "distro": "debian", "suite": "trixie", "arch": "amd64"})),
    ("image build (rpm)", lambda: orch.build_image_cmd(
        {"name": "t", "distro": "rocky", "suite": "9", "arch": "amd64"})),
    ("netboot imager", lambda: orch.build_imager_cmd("amd64")),
    ("update bundle", lambda: orch.build_bundle_cmd("t")),
]

cases = []
for label, make in builders:
    try:
        cases.append((label, make()))
    except Exception as e:  # noqa: BLE001
        # Never swallow this. A command builder that stopped being constructible
        # is a command this test silently stops checking -- which is how the flag
        # would go missing from exactly the path nobody looks at.
        check(f"{label}: command is constructible for inspection ({e!r})", False)

for label, res in cases:
    argv = res[0]
    script = argv[-1] if argv else ""
    runs = [ln for ln in script.splitlines() if "docker run" in ln and "binfmt" not in ln]
    check(f"{label}: has a docker run to inspect", bool(runs))
    for ln in runs:
        check(f"{label}: run line carries --ulimit nofile", "--ulimit nofile=" in ln)

print("== build-image.sh caps it itself, before any package manager ==")
# Relative to this file, like test_builder_image.py: the make target mounts the
# repo root and runs from deploy/builder-runner, so PROJECT_DIR is not the repo.
_here = os.path.dirname(os.path.abspath(__file__))
script_path = os.path.join(_here, "..", "..", "builder", "build-image.sh")
if not os.path.exists(script_path):
    check(f"build-image.sh is mounted at {script_path} to be checked", False)
else:
    body = open(script_path, encoding="utf-8").read()
    # Both. Soft alone is a half-fix that looks like a whole one: the bootstrap
    # gets past glibc and hangs a few packages later, because rpm raises the soft
    # limit back to the hard one before closing anything. Capping soft only took
    # the reproduction from "hangs at package 14" to "hangs at package 40" and
    # nothing else, which is the most expensive kind of partial fix.
    check("lowers the soft limit with ulimit -S -n",
          re.search(r"ulimit\s+-S\s+-n", body) is not None)
    check("lowers the HARD limit too with ulimit -H -n",
          re.search(r"ulimit\s+-H\s+-n", body) is not None)
    # And in that order -- the kernel rejects a hard limit below the live soft one.
    soft_at, hard_at = body.find("ulimit -S -n"), body.find("ulimit -H -n")
    check("soft is lowered before hard (the reverse fails EINVAL)",
          soft_at != -1 and hard_at != -1 and soft_at < hard_at)

    cap = re.search(r"NOFILE_CAP=(\d+)", body)
    check("the cap is a bounded number", cap is not None and 0 < int(cap.group(1)) <= SANE_MAX)

    # Ordering is the whole point: capped *after* the first scriptlet forks is
    # capped too late. Compare against code only -- the comment explaining the
    # bug naturally says "rpm" before the fix does, and a test that trips on its
    # own prose teaches people to delete the prose.
    code = "\n".join(
        "" if ln.lstrip().startswith("#") else ln.split(" #")[0]
        for ln in body.splitlines()
    )
    cap_at = code.find("ulimit -S -n")
    check("the cap is reached in code, not only mentioned", cap_at != -1)
    for tool in ("debootstrap", "dnf ", "rpm "):
        at = code.find(tool)
        check(f"the cap comes before the first use of {tool.strip()!r}",
              at == -1 or (cap_at != -1 and cap_at < at))

print()
if failures:
    print(f"FAILED ({len(failures)}): " + ", ".join(failures))
    sys.exit(1)
print("all nofile checks passed")
