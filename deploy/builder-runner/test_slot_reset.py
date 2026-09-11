"""When the writable state is reconciled against a new slot, and when it is not.

`ab-overlay` clears the distribution-owned paths out of the writable state when
the image underneath them changes. Get that wrong in one direction and a binary
from the old release goes on shadowing the one the update just installed, with
no way to tell from inside the running system -- the failure the reset exists to
prevent, and the one the klibc `rm` bug caused silently for months. Get it wrong
in the other direction and the machine throws away state it had every reason to
keep.

The test it used was "did the slot letter change". That is the right question
only when one upper layer is shared by both slots, which is the default. With
`upper per-slot` each upper is written against its own slot's lower, so an
A -> B switch invalidates nothing: upper-B is exactly as B left it, and B's lower
has not moved. The old test cleared it anyway, on every switch -- so the one
thing `--slot-private-upper` is sold on, each slot keeping its own state, was the
thing it did not do.

What replaced it is the slot's filesystem UUID. RAUC installs an ext4 slot from
a .tar payload, and for that pairing its handler is "make a fresh filesystem and
extract into it" (see the comment in make-bundle.sh), so the UUID changes on
exactly the event that makes an upper stale -- an install into that slot -- and
on nothing else.

Booting a machine twice is not a test anyone runs per change, so the decision is
a pure function of four values and this calls it directly, lifted out of the
script rather than reimplemented. A copy would agree with itself while both
drifted from what actually boots.
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
SCRIPT = os.path.join(ROOT, "builder/overlay/usr/lib/ab/initramfs/ab-overlay")

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


def _extract(name):
    src = open(SCRIPT, encoding="utf-8").read()
    m = re.search(rf"^{name}\(\) \{{.*?^\}}", src, re.S | re.M)
    return m.group(0) if m else None


FN = _extract("reset_reason")
if FN is None:
    print("  FAIL  could not find reset_reason() in ab-overlay")
    sys.exit(1)


def reset_reason(slot, last_slot, lower_id, last_id):
    """Run ab-overlay's own reset_reason. Empty string means 'leave it alone'."""
    prog = FN + '\nreset_reason "$1" "$2" "$3" "$4"\n'
    p = subprocess.run(
        ["sh", "-c", prog, "sh", slot, last_slot, lower_id, last_id],
        capture_output=True, text=True, timeout=30,
    )
    return p.stdout.strip()


def resets(name, args, why=None):
    r = reset_reason(*args)
    ok = bool(r) and (why is None or why in r)
    check(f"resets: {name}", ok, f"got {r!r}")


def keeps(name, args):
    r = reset_reason(*args)
    check(f"keeps:  {name}", r == "", f"expected no reset, got {r!r}")


# UUIDs of two different filesystems. Any two distinct strings would do; these
# are shaped like what blkid returns so a failure reads like the real thing.
A1 = "11111111-1111-1111-1111-111111111111"   # slot A, as first imaged
A2 = "22222222-2222-2222-2222-222222222222"   # slot A, after a bundle install
B1 = "33333333-3333-3333-3333-333333333333"   # slot B, as first imaged

print("== upper per-slot: the bug this fixes ==")

# upper-B was written while B was running, against B's lower. Booting A and then
# back into B changes the slot letter twice and changes B's lower not at all.
# The old rule cleared upper-B on that second switch, every time.
keeps("A -> B, when B's lower has not been touched since upper-B last ran",
      ("B", "A", B1, B1))
keeps("B -> A, likewise, from A's own upper",
      ("A", "B", A1, A1))

# ...but an install into B is exactly what must still clear it.
resets("A -> B after a bundle was installed into B",
       ("B", "A", "44444444-4444-4444-4444-444444444444", B1),
       "was rewritten")

print()
print("== upper shared: unchanged where it was already right ==")

# One upper for both slots, so it carries whatever the last-running slot wrote.
# Switching slots means its contents were written against the other lower.
resets("A -> B clears the shared upper", ("B", "A", B1, A1), "was rewritten")
keeps("rebooting the same slot changes nothing", ("A", "A", A1, A1))
resets("an update to the running slot, then a reboot into it",
       ("A", "A", A2, A1), "was rewritten")

print()
print("== the fallback, for a machine with no stamp yet ==")

# First boot after an update whose new ab-overlay introduced the stamp: the
# identity of the lower is readable but nothing recorded what the upper was last
# reconciled against. Falling back to the slot letter errs towards clearing too
# much, which costs someone a `dnf install` rather than leaving a stale binary
# shadowing a new one.
resets("no stamp and the slot letter changed", ("B", "A", B1, ""), "slot changed")
keeps("no stamp and the same slot", ("A", "A", A1, ""))

# A machine where the UUID could not be read at all -- blkid missing, an
# unexpected slot device. Same fallback, same direction.
resets("no readable UUID and the slot letter changed", ("B", "A", "", ""),
       "slot changed")
keeps("no readable UUID and the same slot", ("A", "A", "", ""))

print()
print("== nothing to compare against ==")

# First boot ever: no previous slot recorded, nothing in the writable state to
# be stale. Clearing here would be clearing an empty store.
keeps("first boot, no previous slot recorded", ("A", "", A1, ""))
keeps("no rauc.slot on the command line and no stamp", ("", "A", "", ""))

# The stamp is written on every boot, not only after a reset, so a boot that
# needed no reset still records what it reconciled against. Without that, the
# first boot after an upgrade would never acquire a stamp and the fallback would
# stay in force forever.
src = open(SCRIPT, encoding="utf-8").read()
stamp_write = re.search(r'\[ -n "\$LOWER_ID" \].*?> "\$STAMP"', src, re.S)
check("the stamp is recorded outside the reset branch", stamp_write is not None)
if stamp_write:
    # It must not sit inside `if [ -n "$NEEDS_RESET" ]; then ... fi`.
    before = src[:stamp_write.start()]
    opened = before.rfind('if [ -n "$NEEDS_RESET" ]; then')
    closed = before.rfind("\nfi")
    check("and not inside it, or a quiet boot would never stamp",
          opened == -1 or closed > opened)

# The helper must not depend on a binary only one of the two initramfs harnesses
# ships. The dracut module lists findmnt; the initramfs-tools hook does not copy
# it -- so a findmnt-based helper would work on AlmaLinux and silently return
# nothing on Debian, putting every Debian machine on the fallback path and making
# it look exactly like a slot that had genuinely changed.
uuid_fn = _extract("lower_fs_uuid")
check("lower_fs_uuid exists", uuid_fn is not None)
if uuid_fn:
    check("it reads /proc/mounts rather than calling findmnt",
          "findmnt" not in uuid_fn and "/proc/mounts" in uuid_fn, uuid_fn)

    # blkid answers from /run/blkid/blkid.tab unless told not to, and that cache
    # is keyed by device path. An entry written before this slot was rewritten
    # reports the filesystem that used to be there -- and "the UUID has not
    # changed" is exactly how this decides the writable state is still valid, so
    # a cached answer would claim an untouched slot after an install replaced it
    # and leave the update's /usr shadowed.
    #
    # This is not hypothetical and was not reasoned out: building a real ext4,
    # reading it through the bind, running mkfs over it and reading again
    # returned the FIRST filesystem's UUID. ab-luks-key carries the same guard.
    check("it bypasses the blkid cache, which would report the old filesystem",
          "-c /dev/null" in uuid_fn, uuid_fn)

    hook = os.path.join(ROOT, "builder/overlay/etc/initramfs-tools/hooks/ab-overlay")
    hook_src = open(hook, encoding="utf-8").read()
    check("blkid, which it does use, is copied by the initramfs-tools hook",
          "blkid" in hook_src)

print()
if failures:
    print(f"FAILED ({len(failures)})")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print(f"all {checks} slot-reset checks passed")
