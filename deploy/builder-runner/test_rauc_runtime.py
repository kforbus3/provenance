"""rauc must still run after the build toolchain is removed.

On the RPM family there is no rauc package, so build-image.sh compiles it from
source and then removes the toolchain. rpm therefore has no record that anything
needs rauc's runtime libraries -- and dnf's clean_requirements_on_remove is on by
default, so removing json-glib-devel takes json-glib with it.

Confirmed on a stock AlmaLinux 9: install json-glib-devel, remove it, and no
json-glib is left, before autoremove is even reached.

The image still builds, verifies, boots and images machines perfectly. rauc is
not used for any of that. The breakage surfaces later, on a machine, in the
middle of the update that rauc exists to perform:

    rauc: error while loading shared libraries: libjson-glib-1.0.so.0:
    cannot open shared object file: No such file or directory

which is exactly how it was found -- a rollout that reached the machine, ran,
and failed there.

Two invariants keep it fixed, and both are easy to undo by accident:

  * the runtime libraries are marked explicitly installed, so the removal leaves
    them alone
  * rauc is verified AFTER the removal, not before

The second is the one that matters most. The build already ran `rauc --version`
BEFORE the cleanup, so it proved the compile worked and nothing proved the image
did. A check on the wrong side of the thing that breaks it is worse than no
check: it reads as coverage.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
BUILD = os.path.join(ROOT, "builder/build-image.sh")

failures = []
checks = 0


def check(name, cond, detail=""):
    global checks
    checks += 1
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        if detail:
            print(f"        {detail}")
        failures.append(name)


print("== rauc survives the removal of its build toolchain ==")

if not os.path.exists(BUILD):
    check("builder/build-image.sh is present", False)
else:
    src = open(BUILD, encoding="utf-8").read()

    remove_at = src.find("dnf -y remove \\$RAUC_BUILD_PKGS")
    check("the toolchain removal is still there to guard", remove_at >= 0,
          "If RAUC_BUILD_PKGS is no longer removed this check needs rewriting, "
          "not deleting — the point is the ordering around it.")

    if remove_at >= 0:
        # Marked before the removal, or the removal takes them.
        mark_at = src.find("dnf -y mark install")
        check("rauc's runtime libraries are marked installed before the removal",
              0 <= mark_at < remove_at,
              "Without `dnf mark install`, dnf treats them as dependencies of the "
              "-devel packages and removes them alongside. Verified on AlmaLinux 9: "
              "marking json-glib keeps it through both remove and autoremove.")

        # Derived from the binary, not a hand-kept list that silently goes stale.
        check("the library list comes from the built binary",
              "ldd /usr/bin/rauc" in src,
              "A hand-written list is one somebody has to remember to update when "
              "rauc changes what it links against.")

        # The verification that matters is the one after the cleanup.
        after = src[remove_at:]
        check("rauc is verified AFTER the toolchain is removed",
              "rauc --version" in after,
              "The build verifies rauc before the cleanup, which proves the compile "
              "worked and not that the shipped image works. Move a `rauc --version` "
              "check below the removal so a build that breaks rauc fails here rather "
              "than on a machine mid-update.")

        # And that it is fatal. A warning would be read by nobody, months later.
        check("a broken rauc fails the build",
              re.search(r"rauc --version[^\n]*\n(?:.*\n)*?\s*exit 1", after) is not None,
              "The post-cleanup check must exit non-zero. An image that cannot "
              "update itself is not a warning-level problem.")

print()
if failures:
    print(f"FAILED ({len(failures)})")
    sys.exit(1)
print(f"all {checks} rauc runtime checks passed")
