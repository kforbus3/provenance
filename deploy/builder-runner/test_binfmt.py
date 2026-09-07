"""The cross-architecture prelude, and which binfmt view it reads.

The bug this pins: the check read /proc/sys/fs/binfmt_misc, which inside this
container is EMPTY no matter what the host has registered. On a host where
`apt install qemu-user-static` had already made arm64 builds work, the build was
refused anyway — the correct configuration being reported as the broken one.
"""

import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("PROJECT_DIR", "/project")

failures = []


def check(name, cond):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        failures.append(name)


import orchestrator  # noqa: E402
importlib.reload(orchestrator)

amd64 = orchestrator._binfmt_prelude("amd64")
arm64 = orchestrator._binfmt_prelude("arm64")

print("== the host's registrations are what get checked ==")
check("the host view is consulted for arm64",
      "/host/binfmt_misc/qemu-aarch64" in arm64)
check("the container's own empty view is not the only source",
      arm64.index("/host/binfmt_misc/qemu-aarch64") < arm64.index("/proc/sys/fs/binfmt_misc/qemu-aarch64"))
check("the unmounted path is still a fallback, so an older deployment is no worse off",
      "/proc/sys/fs/binfmt_misc/qemu-aarch64" in arm64)
check("amd64 checks its own interpreter", "/host/binfmt_misc/qemu-x86_64" in amd64)

print("== it only runs at all when the architectures differ ==")
check("guarded on uname", arm64.startswith('if [ "$(uname -m)" != "aarch64" ]'))
check("an unknown arch produces nothing", orchestrator._binfmt_prelude("riscv64") == "")

print("== a missing interpreter aborts rather than warning ==")
# It used to `|| echo WARNING` and carry on, and the build then died forty lines
# later inside a Dockerfile RUN with a bare "exec format error".
check("the script exits non-zero", "exit 1" in arm64)
check("it does not merely warn", "WARNING: could not register binfmt" not in arm64)
check("both remedies are named",
      "qemu-user-static" in arm64 and "BINFMT_ALLOW=1" in arm64)

print("== the image it runs is the one the proxy is configured with ==")
check("the configured image is used", orchestrator.BINFMT_IMAGE in arm64)

os.environ["BINFMT_IMAGE"] = "tonistiigi/binfmt@sha256:" + "b" * 64
importlib.reload(orchestrator)
pinned = orchestrator._binfmt_prelude("arm64")
check("a pinned digest is carried through", ("sha256:" + "b" * 64) in pinned)
os.environ.pop("BINFMT_IMAGE", None)

print(f"\n{11 - len(failures)} passed, {len(failures)} failed")
sys.exit(1 if failures else 0)
