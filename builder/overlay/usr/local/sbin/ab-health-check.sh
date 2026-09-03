#!/bin/bash
# Decide whether this boot is healthy enough to keep the slot.
#
# Runs every executable in /etc/ab/health.d/ in name order. All pass, the boot
# is healthy and boot-complete.target is reached, which is what lets
# ab-mark-good bless the slot. Any one fails and the target is not reached, the
# slot is never marked good, and the next boot falls back to the other one.
#
# The default image ships no checks at all, and an empty directory is a pass --
# so out of the box "healthy" still means what it meant before: the machine
# booted far enough to permit logins. Adding a check is opt-in and changes what
# an update has to prove before it is kept.
#
# Ship checks through the build's overlay directory:
#
#   overlay.d/etc/ab/health.d/10-app.sh    (chmod +x)
#
# A check is an ordinary script. Exit 0 for healthy, non-zero for not. Keep them
# fast and keep them local: this runs before logins are permitted, so a check
# that blocks is a machine nobody can log in to fix. There is a hard timeout on
# the unit for exactly that reason, and a check that hits it counts as a
# failure.
#
# Deliberately not a general monitoring framework. The only question is "should
# this slot be kept", asked once, on the boot after an update.
set -u

DIR=/etc/ab/health.d
failed=0
ran=0

[ -d "$DIR" ] || { echo "ab-health-check: no $DIR; nothing to check"; exit 0; }

for check in "$DIR"/*; do
    [ -f "$check" ] || continue
    [ -x "$check" ] || {
        # Silently skipping a check someone thought they had installed is the
        # worst outcome available here: the boot would be declared healthy by a
        # check that never ran.
        echo "ab-health-check: $check is not executable; treating as a FAILURE" >&2
        failed=$((failed + 1))
        continue
    }
    ran=$((ran + 1))
    if out="$("$check" 2>&1)"; then
        echo "ab-health-check: PASS $(basename "$check")"
        [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/  /'
    else
        rc=$?
        echo "ab-health-check: FAIL $(basename "$check") (exit $rc)" >&2
        [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/  /' >&2
        failed=$((failed + 1))
    fi
done

if [ "$failed" -gt 0 ]; then
    echo "ab-health-check: $failed of $ran check(s) failed" >&2
    echo "ab-health-check: this slot will NOT be marked good; if it was just" >&2
    echo "  updated, the next boot falls back to the previous slot" >&2
    exit 1
fi

if [ "$ran" = 0 ]; then
    echo "ab-health-check: no checks installed; the boot itself is the check"
else
    echo "ab-health-check: all $ran check(s) passed"
fi
exit 0
