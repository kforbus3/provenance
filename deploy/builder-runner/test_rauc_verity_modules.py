"""An A/B image must load the modules RAUC needs to mount a bundle.

RAUC mounts a verity bundle through device-mapper. Nothing else in these images
uses device-mapper, so unless the build puts the modules in modules-load.d,
nothing loads them -- and every update fails at the LAST step, after the whole
bundle has been fetched over the network and its signature verified:

    20% Verifying signature done.
    30% Checking manifest contents done.
   100% Installing failed.
    LastError: Failed mounting bundle: Failed to open /dev/mapper/control:
               No such file or directory

Load dm_mod alone and it gets one step further and fails again:

    LastError: Failed mounting bundle: Failed to load dm table: Argument list
               too long, check DM_VERITY, DM_CRYPT or CRYPTO_AES kernel options

Both messages read as a problem with the bundle. Neither is. The bundle is
signed, verified and correct; the image is what cannot mount it. And this is the
most expensive place in the whole flow to fail, because the machine has already
downloaded hundreds of megabytes to get there.

Nothing else catches this shape. The build succeeds. The image boots. rauc runs.
`rauc status` is healthy and shows both slots good. The modules are even present
in the kernel tree -- they are simply never loaded, and rauc is the only thing
that would ever want them. docs/imaging.md warns about exactly this class in the
abstract: "the machine images and boots perfectly and only fails the first time
you try to update it -- rauc is used for nothing else."

Found by imaging a machine with this builder and updating it for the first time.
Modprobing both by hand turned a failing install into one that succeeded and
booted the new slot.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(HERE, "..", "..", "builder", "build-image.sh")

failures = []
checks = 0


def check(name, cond):
    global checks
    checks += 1
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        failures.append(name)


print("== the build writes a modules-load.d drop-in for RAUC ==")

if not os.path.exists(BUILD):
    check("build-image.sh is where this test expects it "
          "(mount the repo root, not deploy/builder-runner)", False)
    print(f"\n{checks - len(failures)} passed, {len(failures)} failed")
    sys.exit(1)

src = open(BUILD, encoding="utf-8").read()

check("a file is written under /etc/modules-load.d",
      "/etc/modules-load.d/" in src)
# The directory is created first: debootstrap does not necessarily leave one, and
# a redirect into a missing directory fails the build rather than silently
# skipping -- but only on the distributions that lack it, which is the worst way
# to find out.
check("the directory is created before anything is written into it",
      re.search(r'install -d\s+"\$MNT/etc/modules-load\.d"', src) is not None)

# Both modules. dm_mod alone gets past /dev/mapper/control and then fails on the
# verity target, which is a different error with the same consequence.
for mod in ("dm_mod", "dm_verity"):
    check(f"{mod} is loaded at boot", re.search(rf"'{mod}'", src) is not None)

# Written where RAUC's own configuration is set up, so the two cannot drift apart
# into different distributions' code paths.
i_conf = src.find("/etc/rauc/system.conf")
i_mods = src.find("/etc/modules-load.d/")
check("the drop-in is written alongside the RAUC configuration",
      i_conf != -1 and i_mods != -1 and abs(i_mods - i_conf) < 4000)

print("== and the reason is written down where the next person will look ==")

# A bare `dm_mod` in a config file explains nothing, and the failure it prevents
# is invisible until somebody's first update. The comment is the test's subject
# as much as the module list is.
window = src[max(0, i_mods - 2600):i_mods]
check("the build script explains what breaks without it",
      "verity" in window.lower() and "dev/mapper/control" in window)

print(f"\n{checks - len(failures)} passed, {len(failures)} failed")
sys.exit(1 if failures else 0)
