#!/bin/bash
# Mark the booted A/B slot as proven, so the next boot does not put it on
# probation.
#
# grub.cfg puts a slot on probation only while <SLOT>_PROVEN is 0 -- which is
# what ab-slot-pending.sh sets on the slot an update has just written. It then
# sets <SLOT>_TRY=1 for that one boot, and if nothing clears it the next boot
# falls through to the other slot. This clears it and records that the slot has
# now booted, which is roughly what "rauc status mark-good" would do, without
# depending on the RAUC daemon being configured.
#
# On a slot that is already proven this does nothing at all, so between updates
# neither this nor grub.cfg writes to /boot.
set -u

GRUBENV=/boot/grub/grubenv

# The booted slot comes from the kernel command line (rauc.slot=A|B), with the
# root= label as a fallback.
SLOT=""
for arg in $(cat /proc/cmdline); do
    case "$arg" in
        rauc.slot=A|rauc.slot=B) SLOT="${arg#rauc.slot=}";;
        root=LABEL=rootfs-a) : "${SLOT:=A}";;
        root=LABEL=rootfs-b) : "${SLOT:=B}";;
    esac
done

# Every failure below exits non-zero. It used to exit 0 on all of them, which
# meant `systemctl status ab-mark-good` said "success" on a machine whose try
# counter was still armed -- so the one place anybody would look to explain a
# spontaneous slot switch actively said there was nothing wrong. A machine one
# reboot away from silently changing slots must not look healthy.
if [ -z "$SLOT" ]; then
    echo "ab-mark-good: cannot determine booted slot from /proc/cmdline" >&2
    echo "ab-mark-good: the try counter is still armed; the next boot will use the other slot" >&2
    exit 1
fi
if [ ! -s "$GRUBENV" ]; then
    echo "ab-mark-good: $GRUBENV missing; is /boot mounted?" >&2
    echo "ab-mark-good: the try counter is still armed; the next boot will use the other slot" >&2
    exit 1
fi

# Nothing to do on a slot that is already proven, which after the first boot
# following an update is every boot. Skipping the write keeps an ordinary boot
# from touching /boot at all -- grub.cfg no longer writes either -- so the
# shared BOOT partition is read-only in practice between updates.
if [ "$(grub-editenv "$GRUBENV" list 2>/dev/null | sed -n "s/^${SLOT}_PROVEN=//p")" = "1" ] &&
   [ "$(grub-editenv "$GRUBENV" list 2>/dev/null | sed -n "s/^${SLOT}_TRY=//p")" = "0" ]; then
    echo "ab-mark-good: slot $SLOT was already proven; nothing to do"
    exit 0
fi

# _PROVEN is what stops the next boot putting this slot on probation again;
# _TRY clears the probation this boot was under; _OK is what RAUC reads to
# decide a slot is usable at all, and setting only the counter leaves RAUC
# convinced every slot is bad.
if ! grub-editenv "$GRUBENV" set "${SLOT}_TRY=0" "${SLOT}_OK=1" "${SLOT}_PROVEN=1"; then
    echo "ab-mark-good: could not write $GRUBENV (is /boot read-only?)" >&2
    echo "ab-mark-good: the try counter is still armed; the next boot will use the other slot" >&2
    exit 1
fi

# Read it back rather than trusting the write. grub-editenv writes a temporary
# file and renames it into place, so a full or read-only /boot can fail in ways
# that still exit 0 -- and the symptom of believing a failed write is a machine
# that changes slots by itself on the next reboot, which is not a thing anyone
# traces back to here.
_after="$(grub-editenv "$GRUBENV" list 2>/dev/null)"
if [ "$(printf '%s\n' "$_after" | sed -n "s/^${SLOT}_TRY=//p")" != "0" ] ||
   [ "$(printf '%s\n' "$_after" | sed -n "s/^${SLOT}_PROVEN=//p")" != "1" ]; then
    echo "ab-mark-good: ${SLOT}_TRY/${SLOT}_PROVEN did not stick after writing $GRUBENV" >&2
    echo "ab-mark-good: the try counter is still armed; the next boot will use the other slot" >&2
    exit 1
fi
echo "ab-mark-good: slot $SLOT marked good and proven (${SLOT}_TRY=0 ${SLOT}_PROVEN=1)"
