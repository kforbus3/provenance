#!/bin/bash
# Grow the overlay (last) partition and its filesystem to fill the disk. Handles
# both plain and LUKS-encrypted overlays.
#
# Retries until it actually succeeds. The previous version stamped itself "done"
# and disabled the unit unconditionally — including on the path where nothing
# was grown — so a single transient failure on first boot left the overlay stuck
# at its minimum size forever, with no way to notice. It also sent every error to
# /dev/null, so the journal had nothing to explain why. Both are fixed here: the
# stamp is written only once the filesystem has verifiably grown, and everything
# is logged.
set -u

STAMP=/var/lib/first-boot-expand.done
[ -f "$STAMP" ] && exit 0

# Bumped whenever this script changes behaviour, and logged on every run: an
# image carries a copy of this file baked in at build time, so "did this machine
# get the fix?" is otherwise only answerable by reading the file on the machine.
VERSION=3

log() { echo "first-boot-expand[v$VERSION]: $*"; }

fs_size_bytes() {   # <mountpoint-or-device>
    df -B1 --output=size "$1" 2>/dev/null | tail -1 | tr -d ' '
}

# An image written to a disk larger than itself carries a GPT that still
# describes a disk the size of the image: the backup header sits where the image
# ended, and sgdisk reports "the secondary header's self-pointer indicates that
# it doesn't reside at the end of the disk". growpart copes with this on its own,
# so this is not what blocks expansion — but leaving a knowingly-malformed GPT on
# every deployed machine is not something to ship, and some firmware and
# partition tools do object to it.
fix_gpt() {
    local disk="$1"
    [ -b "$disk" ] || return 0
    command -v sgdisk >/dev/null 2>&1 || return 0
    if sgdisk -v "$disk" 2>&1 | grep -qi "problem"; then
        log "relocating GPT backup header to the end of $disk"
        sgdisk -e "$disk" >/dev/null 2>&1 || log "  sgdisk -e failed (continuing)"
        partprobe "$disk" >/dev/null 2>&1 || partx -u "$disk" >/dev/null 2>&1 || true
    fi
}

# `cryptsetup resize` needs the volume key. Non-interactively it has no way to
# ask, and fails with "Nothing to read on input" — so hand it the same keyfile
# crypttab used to unlock the volume in the first place, when there is one.
crypt_resize() {
    local mapname="$1" keyfile
    keyfile="$(awk -v n="$mapname" '$1==n && $3!="" && $3!="none" {print $3; exit}' /etc/crypttab 2>/dev/null)"
    # crypttab names /cryptkey/luks.key, which exists only inside the initramfs:
    # the key itself lives on the BOOT partition so that an update, which
    # replaces the initramfs, cannot take it away. Mounted, that is /boot.
    if [ ! -r "${keyfile:-}" ] && [ -r /boot/ab-keys/luks.key ]; then
        keyfile=/boot/ab-keys/luks.key
    fi
    if [ -n "${keyfile:-}" ] && [ -r "$keyfile" ]; then
        if cryptsetup resize "$mapname" --key-file "$keyfile"; then
            log "  cryptsetup resize ok (keyfile)"; return 0
        fi
    fi
    # Some setups keep the volume key in the kernel keyring and resize without
    # being handed one.
    if cryptsetup resize "$mapname" </dev/null 2>&1; then
        log "  cryptsetup resize ok"; return 0
    fi
    # Otherwise there is genuinely no way to grow the mapping from here.
    # Reloading the dm-crypt table directly does not help either — LUKS2 keeps
    # the volume key in the kernel keyring, so the ioctl comes back "Required key
    # not available" (tested, not assumed). This is why the unit is ordered
    # before luks-enroll.service: on a tpm2/tang image the bootstrap keyfile is
    # deleted once the volume is enrolled, and the overlay has to be grown while
    # that keyfile still exists.
    log "  cannot resize the encrypted overlay: no usable key"
    log "  (crypttab lists no readable keyfile — has luks-enroll already run?)"
    return 1
}

log "starting"

OVERLAY_FS="$(blkid -L overlay 2>/dev/null || true)"
if [ -z "$OVERLAY_FS" ]; then
    log "no filesystem labelled 'overlay' found; will retry on next boot"
    exit 0
fi

MOUNTPOINT="$(findmnt -nro TARGET -S "$OVERLAY_FS" 2>/dev/null | head -1)"
BEFORE="$(fs_size_bytes "${MOUNTPOINT:-$OVERLAY_FS}")"
log "overlay=$OVERLAY_FS mount=${MOUNTPOINT:-<unmounted>} size=${BEFORE:-?} bytes"

# Resolving "which partition backs this filesystem" has to work for a mapper on
# top of a partition as well as a bare partition. lsblk's PKNAME is the obvious
# route but returns nothing in some environments, and the old script treated that
# empty answer as "no disk", skipped everything, and still marked itself done —
# which is how an overlay ends up stuck at its minimum size permanently. Every
# lookup below therefore has a fallback, and failure is reported, not assumed.
parent_of() {   # <device> -> backing device, or empty
    local dev="$1" pk
    pk="$(lsblk -ndo PKNAME "$dev" 2>/dev/null | head -1)"
    if [ -n "$pk" ]; then echo "/dev/$pk"; return 0; fi
    # dm devices list their backing device under /sys/block/<dm>/slaves.
    local sys
    sys="$(basename "$(readlink -f "$dev" 2>/dev/null)" 2>/dev/null)"
    if [ -n "$sys" ] && [ -d "/sys/block/$sys/slaves" ]; then
        local s
        s="$(ls -1 "/sys/block/$sys/slaves" 2>/dev/null | head -1)"
        [ -n "$s" ] && { echo "/dev/$s"; return 0; }
    fi
    return 1
}

disk_of() {     # <partition> -> whole disk, or empty
    local part="$1" p
    p="$(parent_of "$part" 2>/dev/null || true)"
    if [ -n "$p" ]; then echo "$p"; return 0; fi
    # nvme0n1p6 -> nvme0n1 ; sda6 -> sda ; mmcblk0p2 -> mmcblk0
    case "$part" in
        *[0-9]p[0-9]*) echo "${part%p*}";;
        *)             echo "${part%%[0-9]*}";;
    esac
}

ENCRYPTED=0
case "$OVERLAY_FS" in /dev/mapper/*) ENCRYPTED=1;; esac

if [ "$ENCRYPTED" = 1 ]; then
    MAPNAME="$(basename "$OVERLAY_FS")"
    # cryptsetup knows its own backing device and is the most reliable source.
    CRYPT_PART="$(cryptsetup status "$MAPNAME" 2>/dev/null | awk '/^ *device:/ {print $2; exit}')"
    [ -b "${CRYPT_PART:-}" ] || CRYPT_PART="$(parent_of "$OVERLAY_FS" || true)"
    DISK="$(disk_of "${CRYPT_PART:-}")"
    PARTNUM="$(echo "${CRYPT_PART:-}" | grep -oE '[0-9]+$' || true)"
else
    MAPNAME=""
    CRYPT_PART="$OVERLAY_FS"
    DISK="$(disk_of "$OVERLAY_FS")"
    PARTNUM="$(echo "$OVERLAY_FS" | grep -oE '[0-9]+$' || true)"
fi
log "backing partition=${CRYPT_PART:-<unresolved>} disk=${DISK:-<unresolved>} partnum=${PARTNUM:-<unresolved>}"

if [ ! -b "$DISK" ] || [ -z "$PARTNUM" ]; then
    log "could not resolve backing disk (disk=$DISK part=$PARTNUM); will retry on next boot"
    exit 0
fi

log "growing $DISK partition $PARTNUM"
fix_gpt "$DISK"

if growpart "$DISK" "$PARTNUM"; then
    log "  partition grown"
elif growpart "$DISK" "$PARTNUM" 2>&1 | grep -q NOCHANGE; then
    log "  partition already at full size"
else
    log "  growpart reported no change (see above)"
fi

# Only resize the mapping if it is actually short of its partition. When the
# imager has already grown the partition, dm-crypt was created at full size and
# there is nothing to do -- and since `cryptsetup resize` needs the volume key,
# attempting it anyway logs an alarming "no usable key" on a run that is in fact
# succeeding.
if [ "$ENCRYPTED" = 1 ]; then
    MAP_BYTES="$(blockdev --getsize64 "$OVERLAY_FS" 2>/dev/null || echo 0)"
    PART_BYTES="$(blockdev --getsize64 "$CRYPT_PART" 2>/dev/null || echo 0)"
    # A LUKS2 header is 16 MiB by default; anything within a slack of twice that
    # counts as already spanning the partition.
    if [ "$PART_BYTES" -gt 0 ] && \
       [ "$((PART_BYTES - MAP_BYTES))" -gt "$((32 * 1024 * 1024))" ]; then
        crypt_resize "$MAPNAME"
    else
        log "  dm-crypt mapping already spans the partition; no key needed"
    fi
fi
resize2fs "$OVERLAY_FS" 2>&1 | sed 's/^/  /'

AFTER="$(fs_size_bytes "${MOUNTPOINT:-$OVERLAY_FS}")"
log "filesystem now ${AFTER:-?} bytes (was ${BEFORE:-?})"

# Stamp only on demonstrable success. If the filesystem is no bigger than it was,
# something upstream failed — leave the unit enabled so the next boot tries
# again, by which time the kernel will at least have re-read the partition table.
if [ -n "${AFTER:-}" ] && [ -n "${BEFORE:-}" ] && [ "$AFTER" -gt "$BEFORE" ]; then
    touch "$STAMP"
    systemctl disable first-boot-expand.service >/dev/null 2>&1 || true
    log "done"
else
    log "overlay did not grow; leaving this unit enabled to retry on next boot"
fi
exit 0
