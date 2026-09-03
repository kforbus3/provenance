#!/bin/bash
# Copy this machine's current kernel and initramfs into a slot's directory on
# /boot.
#
# GRUB boots /boot/<A|B>/vmlinuz and /boot/<A|B>/initrd.img -- one pair per slot,
# so an update can replace the inactive slot's kernel without disturbing the one
# the running system depends on. Anything that regenerates the initramfs writes
# to the versioned files at the top of /boot instead, where dpkg and
# update-initramfs expect them, and GRUB never looks. Without this, a
# regenerated initramfs is simply ignored at the next boot.
#
# That matters most for LUKS enrolment: it re-runs update-initramfs so the
# initramfs can unlock via TPM or Tang, and if the slot's copy is stale the
# machine comes up asking for a passphrase nobody is there to type.
#
# Usage: ab-sync-boot [--slot A|B|both] [KVER]
#
#   default      the running slot, from rauc.slot on the kernel command line
#   --slot both  the running slot, and the other one if it is safe (see below)
#
# --- why "both" is not simply two copies -------------------------------------
#
# An initramfs carries the modules of exactly one kernel version, so it may only
# be paired with the kernel it was built for. The running slot is always safe:
# both files come from the same /boot/{vmlinuz,initrd.img}-$KVER. The other slot
# is only safe when it is running that same kernel, which is the case for both
# slots of a freshly imaged machine and stops being the case the moment an A/B
# update puts a new kernel in one of them.
#
# So the other slot is written only when its kernel is byte-identical to ours
# (initramfs alone -- its kernel is already the same file), or when it has no
# kernel at all (both files -- there is nothing there to invalidate). Anything
# else is left alone and said out loud, because silently pairing an initramfs
# with a kernel it was not built for produces a slot that boots to a shell with
# no root filesystem, which is worse than the stale copy it replaced.
set -u

SLOT_ARG=""
KVER=""
while [ $# -gt 0 ]; do
    case "$1" in
        --slot) SLOT_ARG="${2:-}"; shift 2;;
        --slot=*) SLOT_ARG="${1#--slot=}"; shift;;
        -h|--help) sed -n '16,20p' "$0"; exit 0;;
        -*) echo "ab-sync-boot: unknown option '$1'" >&2; exit 1;;
        *)  KVER="$1"; shift;;
    esac
done

SLOT="$(sed -n 's/.*rauc\.slot=\([AB]\).*/\1/p' /proc/cmdline 2>/dev/null)"
[ -n "$SLOT" ] || { echo "ab-sync-boot: no rauc.slot on the command line" >&2; exit 1; }
case "$SLOT" in A) OTHER=B;; B) OTHER=A;; esac

KVER="${KVER:-$(uname -r)}"
SRC_K="/boot/vmlinuz-${KVER}"
SRC_I="/boot/initrd.img-${KVER}"
[ -f "$SRC_K" ] || { echo "ab-sync-boot: no $SRC_K" >&2; exit 1; }
[ -f "$SRC_I" ] || { echo "ab-sync-boot: no $SRC_I" >&2; exit 1; }

# Written alongside and renamed into place: a half-copied kernel in the slot's
# directory is a machine that does not boot, and this runs on a live system
# where losing power mid-copy is a real possibility.
install_file() {               # install_file <src> <dst>
    cp -f "$1" "$2.new" || return 1
    sync
    mv -f "$2.new" "$2" || return 1
    sync
}

sync_running_slot() {
    mkdir -p "/boot/${SLOT}"
    install_file "$SRC_K" "/boot/${SLOT}/vmlinuz"    || return 1
    install_file "$SRC_I" "/boot/${SLOT}/initrd.img" || return 1
    echo "ab-sync-boot: slot ${SLOT} now boots kernel ${KVER}"
}

# The other slot's root filesystem is not mounted and must not be touched; only
# its kernel pair under /boot is, and only under the conditions above.
sync_other_slot() {
    local dst="/boot/${OTHER}"
    if [ ! -f "$dst/vmlinuz" ]; then
        mkdir -p "$dst"
        install_file "$SRC_K" "$dst/vmlinuz"    || return 1
        install_file "$SRC_I" "$dst/initrd.img" || return 1
        echo "ab-sync-boot: slot ${OTHER} had no kernel; installed ${KVER}"
        return 0
    fi
    if cmp -s "$SRC_K" "$dst/vmlinuz"; then
        install_file "$SRC_I" "$dst/initrd.img" || return 1
        echo "ab-sync-boot: slot ${OTHER} runs the same kernel; its initramfs updated too"
        return 0
    fi
    echo "ab-sync-boot: slot ${OTHER} runs a different kernel; left alone." >&2
    echo "  Its initramfs belongs to that kernel and pairing it with ${KVER}" >&2
    echo "  would leave it unbootable. Rebuild that slot from an image instead." >&2
    return 2
}

sync_running_slot || exit 1

case "${SLOT_ARG:-}" in
    ""|"$SLOT")   ;;
    # Exit 2 is "the other slot runs a different kernel", which is a legitimate
    # state and not a failure of this command; anything else is a real error.
    both|all)     sync_other_slot; rc=$?; [ "$rc" = 0 ] || [ "$rc" = 2 ] || exit 1;;
    "$OTHER")     echo "ab-sync-boot: refusing --slot ${OTHER} while running ${SLOT};" >&2
                  echo "  use --slot both (this machine's kernel is the only one it has)." >&2
                  exit 1;;
    *)            echo "ab-sync-boot: --slot must be A, B or both" >&2; exit 1;;
esac

exit 0
