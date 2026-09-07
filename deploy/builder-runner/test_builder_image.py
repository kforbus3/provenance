"""Which builder image a distribution gets, and whether the two lists agree.

The bug this pins: build-image.sh grew an rpm FAMILY and the orchestrator kept
running the Debian builder for every build. The bootstrap is `dnf --installroot`
and there is no dnf in that image, so a Rocky build partitioned the disk, set up
LUKS, formatted, mounted -- and then died on `dnf: command not found`, twenty
minutes in, at the first step that was actually distribution-specific.
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


print("== each family gets its own builder ==")
for d in ("almalinux", "rocky", "rhel"):
    df, fam = orch.builder_image_for(d)
    check(f"{d} builds from Dockerfile.rpm", df == "Dockerfile.rpm" and fam == "rpm")
for d in ("debian", "ubuntu"):
    df, fam = orch.builder_image_for(d)
    check(f"{d} builds from Dockerfile", df == "Dockerfile" and fam == "deb")

print("== an unknown distribution falls back to deb ==")
# build-image.sh defaults an unrecognised distro to the deb path and fails there
# with its own message. Guessing rpm here would disagree with it, and the
# disagreement would surface as a missing debootstrap rather than a bad --distro.
for d in ("", "suse", "arch", None):
    df, fam = orch.builder_image_for(d if d is not None else "")
    check(f"{d!r} falls back to deb", fam == "deb")

print("== case and whitespace do not change the answer ==")
for d in ("Rocky", "  rocky  ", "ALMALINUX"):
    check(f"{d!r} is still rpm", orch.builder_image_for(d)[1] == "rpm")

print("== the tag stays inside the socket proxy's allowlist ==")
# The proxy matches ^debian-ab-builder(:[\w.\-]+)?$ and allows it privileged.
# A NAME change would need that allowlist widened; a tag does not.
allow = re.compile(r"^debian-ab-(builder|imager)(:[\w.\-]+)?$")
for fam in ("deb", "rpm"):
    for arch in ("amd64", "arm64"):
        tag = f"debian-ab-builder:{fam}-{arch}"
        check(f"{tag} is allowlisted", bool(allow.match(tag)))

print("== the two family lists agree with build-image.sh ==")
# One list here, one `case` there. They disagree only if somebody adds a
# distribution to one and not the other -- which is exactly how this broke.
here = os.path.dirname(os.path.abspath(__file__))
script = os.path.join(here, "..", "..", "builder", "build-image.sh")
if os.path.isfile(script):
    body = open(script).read()
    m = re.search(r"^\s*(almalinux[|\w]*)\)\s*FAMILY=rpm", body, re.M)
    listed = set(m.group(1).split("|")) if m else set()
    check(f"build-image.sh rpm distros {sorted(listed)} match orchestrator's",
          listed == set(orch.RPM_DISTROS))
else:
    check("build-image.sh found for cross-check", False)

print(f"\n{16 - len(failures)} passed, {len(failures)} failed")
sys.exit(1 if failures else 0)
