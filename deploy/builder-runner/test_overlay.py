"""Overlay writes, including the binary ones.

`content` is a str and always was, so anything not valid UTF-8 -- a certificate,
a compiled tool, a firmware blob -- could not be written at all, and the overlay
is exactly where those belong. These cover the base64 path that fixes it, and the
containment that has to hold whichever way bytes arrive.
"""

import base64
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_tmp = tempfile.mkdtemp()
os.environ["PROJECT_DIR"] = _tmp
os.makedirs(os.path.join(_tmp, "overlay.d"), exist_ok=True)

import orchestrator as orch  # noqa: E402

failures = []


def check(name, cond):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        failures.append(name)


print("== bytes survive the round trip ==")
# A PNG header and an embedded NUL: not UTF-8, and the exact shape that a
# text-only write path mangles rather than refuses.
blob = b"\x89PNG\r\n\x1a\n\x00\x01\x02\xff\xfe binary \x00 tail"
orch.overlay_write("/usr/local/share/thing.bin", blob, 0o644)
back = open(os.path.join(_tmp, "overlay.d", "usr/local/share/thing.bin"), "rb").read()
check("a binary file is stored byte-identical", back == blob)
check("base64 of it decodes to the same bytes",
      base64.b64decode(base64.b64encode(blob)) == blob)

print("== the mode is part of the file ==")
orch.overlay_write("/usr/local/sbin/run.sh", b"#!/bin/sh\nexit 0\n", 0o755)
st = os.stat(os.path.join(_tmp, "overlay.d", "usr/local/sbin/run.sh"))
check("0755 is what lands", (st.st_mode & 0o777) == 0o755)
listed = {f["path"]: f for f in orch.overlay_files()}
check("and is reported back", listed["/usr/local/sbin/run.sh"]["mode"] == "0755")
check("executable is reported", listed["/usr/local/sbin/run.sh"]["executable"] is True)
check("a data file is not executable", listed["/usr/local/share/thing.bin"]["executable"] is False)

print("== containment holds for uploads too ==")
# An upload names its own path, and a folder upload names one per file. Every one
# of them is attacker-controlled in exactly the way a typed path is.
for bad in ("../../etc/shadow", "/../../etc/shadow", "/etc/../../x", "/a/../../b"):
    try:
        orch.overlay_write(bad, b"x", None)
        check(f"{bad} is refused", False)
    except orch.OverlayPathError:
        check(f"{bad} is refused", True)
    except OSError:
        check(f"{bad} is refused", False)

print("== a deep tree is created on the way ==")
orch.overlay_write("/a/b/c/d/deep.conf", b"k=v\n", None)
check("intermediate directories are made",
      os.path.isfile(os.path.join(_tmp, "overlay.d", "a/b/c/d/deep.conf")))

print("== the reserved name stays reserved ==")
try:
    orch.overlay_write("/README.md", b"x", None)
    check("README.md is refused", False)
except orch.OverlayPathError:
    check("README.md is refused", True)

print(f"\n{13 - len(failures)} passed, {len(failures)} failed")
sys.exit(1 if failures else 0)
