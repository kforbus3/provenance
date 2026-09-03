#!/bin/bash
# Put the slot an update has just written on probation.
#
# This is the other half of grub.cfg's <SLOT>_PROVEN check, and the reason the
# A/B fallback can be armed for updates only rather than for every boot.
#
# grub.cfg gives a slot one attempt while _PROVEN=0: it sets _TRY=1, and if
# ab-mark-good does not clear that during the boot, the next boot uses the other
# slot. A proven slot is simply booted. So something has to say "this slot is
# new again" at exactly the moment its contents are replaced, and that is here.
#
# Run as RAUC's post-install handler ([handlers] post-install in system.conf),
# NOT from ab-update.sh. RAUC runs it however the install was started, so
# `rauc install <bundle>` typed by hand -- which make-bundle.sh prints as the
# install command, and which the web UI shows -- gets the same protection as
# `ab-update`. Wiring it into the wrapper instead would have left the documented
# hand-run path installing updates with no rollback at all.
#
# Best-effort by design. RAUC treats a failing post-install handler as a failed
# installation, and by this point the slot is already written -- reporting the
# whole update as failed because a grubenv variable could not be set would be a
# worse outcome than an update that boots without probation. It is loud in the
# install log instead, and ab-update.sh repeats the call for the same reason.
set -u

GRUBENV=/boot/grub/grubenv

# Which slot was written. RAUC exports the running slot's bootname; with exactly
# two slots the target is the other one, which avoids depending on the spelling
# of RAUC's per-slot target variables. Falls back to the kernel command line
# when the handler is run by hand.
CURRENT="${RAUC_CURRENT_BOOTNAME:-}"
if [ -z "$CURRENT" ]; then
    for arg in $(cat /proc/cmdline 2>/dev/null); do
        case "$arg" in
            rauc.slot=A|rauc.slot=B) CURRENT="${arg#rauc.slot=}";;
        esac
    done
fi

case "$CURRENT" in
    A) TARGET=B;;
    B) TARGET=A;;
    *)
        echo "ab-slot-pending: cannot tell which slot is running (RAUC_CURRENT_BOOTNAME='${RAUC_CURRENT_BOOTNAME:-}')" >&2
        echo "ab-slot-pending: the updated slot will boot WITHOUT an automatic fallback" >&2
        exit 0;;
esac

if [ ! -s "$GRUBENV" ]; then
    echo "ab-slot-pending: $GRUBENV missing; is /boot mounted?" >&2
    echo "ab-slot-pending: slot $TARGET will boot WITHOUT an automatic fallback" >&2
    exit 0
fi

# _TRY=0 as well as _PROVEN=0: the slot may still be carrying a spent counter
# from the last time it was on probation, and a slot that is unproven with its
# counter already at 1 is one grub.cfg will refuse to boot at all.
if ! grub-editenv "$GRUBENV" set "${TARGET}_PROVEN=0" "${TARGET}_TRY=0"; then
    echo "ab-slot-pending: could not write $GRUBENV" >&2
    echo "ab-slot-pending: slot $TARGET will boot WITHOUT an automatic fallback" >&2
    exit 0
fi

# Read back, for the same reason ab-mark-good does: a write that silently did
# not happen means an update installs, boots, fails, and never rolls back --
# and nothing would have said so at the one moment someone was watching.
if [ "$(grub-editenv "$GRUBENV" list 2>/dev/null | sed -n "s/^${TARGET}_PROVEN=//p")" != "0" ]; then
    echo "ab-slot-pending: ${TARGET}_PROVEN did not stick after writing $GRUBENV" >&2
    echo "ab-slot-pending: slot $TARGET will boot WITHOUT an automatic fallback" >&2
    exit 0
fi

echo "ab-slot-pending: slot $TARGET is on probation for its next boot"
exit 0
