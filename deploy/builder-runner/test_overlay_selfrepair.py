"""The unit that repairs the overlay must be able to run when the overlay is broken.

first-boot-expand grows the overlay partition and its filesystem. It carried

    RequiresMountsFor=/var/lib/overlay

which is a hard requirement, so when the overlay could not be mounted systemd
refused to start it at all:

    Dependency failed for first-boot-expand.service - Grow overlay partition ...

Repairing an overlay that will not mount is exactly what this unit is for, so the
dependency prevented the one thing it exists to do. A machine whose overlay
filesystem is larger than its partition -- what an interrupted re-image leaves,
because the partition table is restored from the image before the overlay's
contents are -- booted with

    EXT4-fs (sda6): bad geometry: block count 15071212 exceeds size of device
    ab-overlay: overlay filesystem would not mount -- booting the slot directly

and stayed that way. Everything looked fine: it booted, rauc status was healthy,
an A/B update installed and activated the other slot. The only signals were one
dmesg line and the word "degraded". Nothing persisted across updates, which is the
opposite of what the default state model promises -- "/etc, /home, /opt, /srv,
/var and /usr/local are all still there afterwards".

Both halves have been wrong in turn, which is why this is pinned. The unit first
ran too early, found no device, and stamped itself done permanently; that was
fixed by making the mount a requirement, which overshot. Ordering is what was
wanted.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
UNIT = os.path.join(HERE, "..", "..", "builder", "overlay", "etc", "systemd",
                    "system", "first-boot-expand.service")
SCRIPT = os.path.join(HERE, "..", "..", "builder", "overlay", "usr", "local",
                      "sbin", "first-boot-expand.sh")

failures = []
checks = 0


def check(name, cond):
    global checks
    checks += 1
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        failures.append(name)


print("== the unit can run when the overlay will not mount ==")

if not (os.path.exists(UNIT) and os.path.exists(SCRIPT)):
    check("the unit and script are where this test expects them", False)
    print(f"\n{checks - len(failures)} passed, {len(failures)} failed")
    sys.exit(1)

unit = open(UNIT, encoding="utf-8").read()
# Directives only: the comments explain the requirement that was removed, and a
# check that cannot tell a directive from an explanation fails on the comment
# documenting the fix.
directives = [ln.strip() for ln in unit.splitlines()
              if ln.strip() and not ln.lstrip().startswith("#")]

check("it does not REQUIRE the overlay mount",
      not any(re.match(r"RequiresMountsFor=.*overlay", d) for d in directives))
check("it is still ORDERED after the overlay mount",
      any("After=" in d and "overlay" in d for d in directives))
# /boot is a different matter: the LUKS bootstrap key lives there and a resize of
# an encrypted overlay genuinely cannot proceed without it.
check("/boot is still required (the LUKS key lives there)",
      any(d == "RequiresMountsFor=/boot" for d in directives))
# The guard that stops it running once it has succeeded.
check("it still skips itself once done",
      any("ConditionPathExists=!" in d for d in directives))

print("== and the script can repair a filesystem that needs checking ==")

script = open(SCRIPT, encoding="utf-8").read()
code = "\n".join(ln for ln in script.splitlines() if not ln.lstrip().startswith("#"))

check("it runs e2fsck when resize2fs will not proceed", "e2fsck" in code)
check("only in non-interactive preen mode (a prompt would hang the boot)",
      re.search(r"e2fsck\s+-fp\b", code) is not None)
check("and only while the overlay is unmounted (e2fsck on a mounted fs corrupts it)",
      re.search(r'\[ -z "\$\{MOUNTPOINT:?-?\}?" \]', code) is not None
      or re.search(r'-z "\$\{MOUNTPOINT:-\}"', code) is not None)
# Order matters: the partition has to be grown before the filesystem is checked
# against it, or the check just confirms the mismatch.
i_grow = code.find("growpart")
i_fsck = code.find("e2fsck")
check("the partition is grown before the filesystem is checked",
      i_grow != -1 and i_fsck != -1 and i_grow < i_fsck)

print(f"\n{checks - len(failures)} passed, {len(failures)} failed")
sys.exit(1 if failures else 0)
