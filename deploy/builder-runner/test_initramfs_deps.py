"""Every command the boot scripts call must be installed into the initramfs.

The bug this pins cost a machine its unattended boot, twice over.

`ab-luks-key` is the hook that stages this machine's LUKS bootstrap key so the
root filesystem can be opened without anyone typing anything. It called
`dirname`. A dracut initramfs is not a distribution — it contains exactly the
binaries a module asks for and nothing else — and the module did not ask for
`dirname`. So the hook ran, printed

    /usr/lib/ab/initramfs/ab-luks-key: line 63: dirname: command not found
    mkdir: cannot create directory '': No such file or directory

made no keyfile, and the disk fell through to a passphrase prompt on a machine
that had just been imaged unattended and had nobody in front of it.

Nothing catches that shape. It is not a syntax error; the script is valid. It is
not a missing package; there is no package manager. The build succeeds, the
initramfs verifies, the hook is present and runnable, and the failure appears
only on a booting machine as one line among hundreds of systemd messages.

`ab-overlay` had the same gap for `cat` and `mv`, and its own comments already
record an earlier round of it: klibc ships `nuke` rather than `rm`, so every
`rm -rf` in the overlay script failed silently for months and an A/B update left
the previous release's /usr shadowing the one just installed.

So: extract the commands each shared script actually calls, and require the
matching dracut module to install them.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))

# script -> the dracut module that installs it
PAIRS = [
    ("builder/overlay/usr/lib/ab/initramfs/ab-luks-key",
     "builder/overlay/usr/lib/dracut/modules.d/91ab-luks-key/module-setup.sh"),
    ("builder/overlay/usr/lib/ab/initramfs/ab-overlay",
     "builder/overlay/usr/lib/dracut/modules.d/90ab-overlay/module-setup.sh"),
]

# External commands worth checking. Deliberately a list rather than "every word
# that looks like a command": shell builtins (echo, printf, test, read, local)
# are always available and would be noise, and noise is how a check stops being
# read.
EXTERNAL = [
    "awk", "basename", "blkid", "cat", "chmod", "chown", "cp", "cut", "dirname",
    "find", "findmnt", "grep", "head", "ln", "losetup", "mkdir", "modprobe",
    "mount", "mv", "readlink", "rm", "rmdir", "sed", "sort", "stat", "sync",
    "touch", "tr", "udevadm", "umount",
]

# Commands a dracut initramfs always has from its own base modules, so a module
# need not name them. Keep this short and justified — every entry is a claim
# that something is present without asking for it.
ALWAYS = {
    # dracut's base module installs a shell and the coreutils it needs for its
    # own hooks; sh builtins aside, these are the ones it guarantees.
    "sync",
}

failures = []
checks = 0


def check(name, cond):
    global checks
    checks += 1
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        failures.append(name)


def commands_used(path):
    """Commands invoked by a shell script, ignoring comments."""
    src = open(path, encoding="utf-8").read()
    code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
    found = []
    for c in EXTERNAL:
        # Start of a line, or after a separator, or inside $( ) / backticks.
        if re.search(rf"(?:^|[;&|(]|\$\(|`|\bthen\b|\belse\b|\bdo\b)\s*{re.escape(c)}\s",
                     code, re.M):
            found.append(c)
    return found


def commands_installed(path):
    """Commands a module-setup.sh installs via inst_multiple."""
    src = open(path, encoding="utf-8").read()
    got = set()
    for line in src.splitlines():
        line = line.strip()
        if not line.startswith("inst_multiple"):
            continue
        for tok in line.split()[1:]:
            if tok.startswith("-"):      # -o marks the rest optional; still installed
                continue
            got.add(os.path.basename(tok))
    # inst_script/inst_simple of the script itself is not a command it can call.
    return got


print("== the initramfs contains every command these scripts call ==")
for script_rel, module_rel in PAIRS:
    script = os.path.join(ROOT, script_rel)
    module = os.path.join(ROOT, module_rel)
    name = os.path.basename(script)

    if not (os.path.exists(script) and os.path.exists(module)):
        check(f"{name}: script and module-setup.sh both present", False)
        continue

    used = set(commands_used(script))
    have = commands_installed(module) | ALWAYS
    missing = sorted(used - have)

    if missing:
        check(f"{name} calls {missing}, which its module does not install", False)
        print(f"        Add them to inst_multiple in {module_rel}, or stop calling")
        print("        them. A command that is not installed is not missing at build")
        print("        time — it is a shell error on a booting machine.")
    else:
        check(f"{name}: all {len(used)} commands it calls are installed", True)

# The specific one that got away, named so a future edit that reintroduces it
# fails loudly rather than subtly.
luks = os.path.join(ROOT, PAIRS[0][0])
if os.path.exists(luks):
    body = "\n".join(l for l in open(luks, encoding="utf-8").read().splitlines()
                     if not l.lstrip().startswith("#"))
    check("ab-luks-key does not use dirname (its paths are constants)",
          "dirname" not in body)

def check_ordering_unit():
    """The key hook must be ordered before anything tries to unlock a volume.

    The hook alone runs at initqueue/settled, which in a systemd initrd is AFTER
    the cryptsetup units have started. A volume that is not the root slot is
    asked for exactly once: it found no keyfile and fell through to a passphrase
    prompt, on a machine that had the correct key on its own BOOT partition.

    Everything else about that image was right -- two keyslots per volume, the
    keyfile opening all three, the hook present and runnable. Only the ordering
    was wrong, so every check passed and the machine still would not boot.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.normpath(os.path.join(here, "..", ".."))
    mod = os.path.join(root, "builder/overlay/usr/lib/dracut/modules.d/91ab-luks-key")
    unit = os.path.join(mod, "ab-luks-key.service")
    setup = os.path.join(mod, "module-setup.sh")

    ok = True
    if not os.path.exists(unit):
        check("the ordering unit ab-luks-key.service exists", False); ok = False
    else:
        body = open(unit, encoding="utf-8").read()
        check("the unit is ordered Before=cryptsetup-pre.target",
              "Before=cryptsetup-pre.target" in body)
        check("the unit waits for devices to be enumerated",
              "systemd-udev-trigger" in body)
        # A failure to stage the key must not wedge the machine: the passphrase
        # prompt is the fallback and has to stay reachable.
        check("a failure does not block the boot",
              "SuccessExitStatus" in body or "TimeoutStartSec" in body)

    if os.path.exists(setup):
        body = open(setup, encoding="utf-8").read()
        check("module-setup.sh installs the unit",
              "ab-luks-key.service" in body and "inst_simple" in body)
        check("and enables it, or it is installed and never started",
              "sysinit.target.wants" in body)
    else:
        check("module-setup.sh is present", False); ok = False
    return 0 if ok else 1


check_ordering_unit()

print()
if failures:
    print(f"FAILED ({len(failures)})")
    sys.exit(1)
print(f"all {checks} initramfs dependency checks passed")
