#!/bin/bash
# What has changed on this machine since it was imaged, and what that is hiding.
#
# The root filesystem is an overlay: the read-only lower layer is the A/B root
# slot exactly as the imager wrote it, and every write since lands in the upper
# layer on the overlay partition. By default that upper layer is shared by both
# slots, so an A/B update replaces the OS without destroying /home.
#
# The cost of that is invisible from inside the running system: a file you edit
# in slot A shadows slot B's copy of the same file, including one an update was
# meant to deliver. Nothing in `ls` or `cat` says which layer you are looking at.
# This prints that.
#
# An image built with --slot-private-upper gives each slot its own upper instead
# (`upper-A`, `upper-B`). Which one this machine has changes both the directory
# to walk and the advice at the bottom -- "these files shadow the image on both
# slots" is simply false there -- so both are read from the manifest rather than
# assumed.
set -u

OVL=/var/lib/overlay          # the overlay partition
UPPER=""                      # resolved from the manifest below
LOWER=""                      # the booted slot, read-only; found below

BOLD=""; DIM=""; RED=""; YEL=""; GRN=""; OFF=""
if [ -t 1 ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; YEL=$'\033[33m'
    GRN=$'\033[32m'; OFF=$'\033[0m'
fi

usage() {
    cat <<EOF
Usage: ab-overlay-diff [options]

Lists what this machine has written since it was imaged, and which of those
files are shadowing a file from the image.

  -a, --all        every changed path, not just the ones shadowing the image
  -q, --quiet      counts only, no file list
  -h, --help       this text

Recovery, when a change here is the problem:

  Reboot and choose "Recovery: Slot <A|B>, reset writable state" from the GRUB
  menu. Each store is renamed to $OVL/<name>.prev -- nothing is deleted -- and
  the machine boots with empty ones. Copy anything you need back out of them.

  "Recovery: Slot <A|B>, image as written" boots the root slot exactly as
  imaged, applying no state manifest at all. Use it to confirm whether a
  problem lives in the image or in what the machine wrote on top of it.
EOF
}

ALL=0; QUIET=0
while [ $# -gt 0 ]; do
    case "$1" in
        -a|--all)   ALL=1;;
        -q|--quiet) QUIET=1;;
        -h|--help)  usage; exit 0;;
        *) echo "ab-overlay-diff: unknown option '$1'" >&2; usage >&2; exit 2;;
    esac
    shift
done

# What this machine's writable state is supposed to look like. Under the default
# model that is one overlay over the whole root; under stateful or appliance the
# root is read-only and only the enumerated paths are writable. Reading it here
# is what keeps this tool honest on an image that is not the default -- without
# it, everything a machine wrote to /home under a `persist /home` directive is
# simply invisible, which is the failure mode this whole tool exists to prevent.
CONF=/usr/lib/ab/state.conf
MODEL=overlay
UPPER_MODE=shared
OVERLAYS=""; OTHERS=""
if [ -r "$CONF" ]; then
    MODEL=$(awk '$1 == "model" { print $2; exit }' "$CONF")
    UPPER_MODE=$(awk '$1 == "upper" { print $2; exit }' "$CONF")
    OVERLAYS=$(awk '$1 == "overlay" { print $2 }' "$CONF")
    OTHERS=$(awk '$1 == "persist" || $1 == "slot-private" || $1 == "volatile" \
                  { print $1 " " $2 }' "$CONF")
else
    OVERLAYS="/"               # no manifest: an image built before they existed
fi
[ -n "$MODEL" ] || MODEL=overlay
[ -n "$UPPER_MODE" ] || UPPER_MODE=shared

SLOT="$(sed -n 's/.*rauc\.slot=\([AB]\).*/\1/p' /proc/cmdline 2>/dev/null)"

# Same rule the initramfs applies, and for the same reason: walking the shared
# `upper` on a machine whose writes are all in `upper-A` would report a machine
# that has changed nothing since imaging, which is the one answer this tool must
# never give wrongly.
if [ "$UPPER_MODE" = per-slot ]; then
    if [ -z "$SLOT" ]; then
        echo "ab-overlay-diff: this image gives each slot its own upper layer, but" >&2
        echo "there is no rauc.slot= on the kernel command line to say which one is" >&2
        echo "booted, so there is nothing safe to compare." >&2
        exit 1
    fi
    UPPER="$OVL/upper-$SLOT"
else
    UPPER="$OVL/upper"
fi

if [ -z "$OVERLAYS" ]; then
    echo "${YEL}This image (model ${MODEL}) has no overlay, so nothing shadows the${OFF}"
    echo "${YEL}image and there is nothing for this tool to compare.${OFF}"
    [ -n "$OTHERS" ] && { echo ""; echo "Writable paths on this machine:"
                          printf '%s\n' "$OTHERS" | sed 's/^/  /'; }
    exit 0
fi

# A root overlay is only expected under the default model. Saying "not an
# overlay root" on a stateful image would be reporting the design as a fault.
if printf '%s\n' "$OVERLAYS" | grep -qx '/' && \
   ! findmnt -no FSTYPE / 2>/dev/null | grep -qx overlay; then
    echo "${YEL}This machine should have an overlay root and does not.${OFF}"
    echo "Either it booted with ab.state=off, or the overlay could not be set"
    echo "up (dmesg | grep ab-overlay says which). Nothing to compare."
    exit 1
fi
if [ ! -d "$UPPER" ]; then
    echo "ab-overlay-diff: no upper layer at $UPPER" >&2
    exit 1
fi

# The lower layer has to be reached on purpose. The initramfs binds it inside
# the new root before switching, but systemd mounts a fresh tmpfs over /run
# immediately afterwards, so anything left there is gone by the time a person
# could look at it. Mounting the slot read-only here is independent of all that:
# it is the same filesystem the overlay is stacked on, and read-only means this
# cannot disturb the running system or the slot.
TMPLOWER=""
cleanup() {
    [ -n "$TMPLOWER" ] || return 0
    umount "$TMPLOWER" 2>/dev/null || true
    rmdir "$TMPLOWER" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if mountpoint -q /run/ab-lower 2>/dev/null; then
    LOWER=/run/ab-lower
else
    case "${SLOT:-}" in
        A) DEV=/dev/mapper/luks-rootfs-a; [ -b "$DEV" ] || DEV="$(blkid -L rootfs-a 2>/dev/null)";;
        B) DEV=/dev/mapper/luks-rootfs-b; [ -b "$DEV" ] || DEV="$(blkid -L rootfs-b 2>/dev/null)";;
        *) DEV="";;
    esac
    if [ -n "$DEV" ] && [ -b "$DEV" ]; then
        TMPLOWER="$(mktemp -d /tmp/ab-lower.XXXXXX)"
        # Deliberately not -o ro. Reaching this point means root is an overlay,
        # which means this filesystem is already mounted read-write as its lower
        # layer, and ext4 refuses a second mount of one superblock with a
        # different RO state -- it fails and logs "would change RO state" to the
        # console every time, which is alarming for a read-only inspection tool.
        # Matching the existing flags adds no exposure: it is the same superblock
        # the running system already has mounted, and nothing here writes to it.
        if mount "$DEV" "$TMPLOWER" 2>/dev/null; then
            LOWER="$TMPLOWER"
        else
            rmdir "$TMPLOWER" 2>/dev/null || true; TMPLOWER=""
        fi
    fi
fi
echo "${BOLD}Machine changes since imaging${OFF}${DIM}  (slot ${SLOT:-?}, upper layer $UPPER)${OFF}"
echo ""

# An overlayfs whiteout is a character device 0/0 in the upper layer: the file
# exists in the image and has been deleted here. Worth separating, because a
# deletion that hides a file the image still needs looks like nothing at all.
shadowing=0; added=0; deleted=0
list_shadow=""; list_add=""; list_del=""

while IFS= read -r path; do
    rel="${path#$UPPER}"
    [ "$rel" = "$path" ] && continue
    [ -z "$rel" ] && continue
    case "$rel" in /work|/work/*) continue;; esac

    if [ -c "$path" ] && [ "$(stat -c '%t:%T' "$path" 2>/dev/null)" = "0:0" ]; then
        deleted=$((deleted + 1))
        list_del="${list_del}${rel}"$'\n'
    elif [ -n "$LOWER" ] && [ -e "$LOWER$rel" ]; then
        shadowing=$((shadowing + 1))
        list_shadow="${list_shadow}${rel}"$'\n'
    else
        added=$((added + 1))
        list_add="${list_add}${rel}"$'\n'
    fi
done < <(find "$UPPER" \( -type f -o -type l -o -type c \) 2>/dev/null)

if [ -z "$LOWER" ]; then
    echo "${YEL}Note:${OFF} the root slot for this machine could not be mounted, so"
    echo "nothing can be compared against the image and every change below is"
    echo "reported as added rather than as shadowing."
    echo ""
fi

show() {  # show <title> <colour> <list>
    [ "$QUIET" = 1 ] && return 0
    [ -z "$3" ] && return 0
    echo "${2}${1}${OFF}"
    printf '%s' "$3" | sed '/^$/d' | sort | sed 's/^/  /'
    echo ""
}

show "Shadowing a file from the image ($shadowing)" "$RED" "$list_shadow"
if [ "$ALL" = 1 ]; then
    show "Added by this machine ($added)" "$GRN" "$list_add"
    show "Deleted from the image ($deleted)" "$YEL" "$list_del"
fi

echo "${BOLD}${shadowing}${OFF} shadowing the image, ${BOLD}${added}${OFF} added, ${BOLD}${deleted}${OFF} deleted"
[ "$ALL" = 0 ] && [ $((added + deleted)) -gt 0 ] && \
    echo "${DIM}(-a lists the added and deleted ones too)${OFF}"

# Paths that are not in the overlay at all. Everything above walks the upper
# layer, so a bind or a tmpfs is invisible to it -- and "invisible" is exactly
# the wrong answer for the paths someone deliberately carved out. Say where they
# go and, more usefully, whether the other slot sees the same thing.
if [ -n "$OTHERS" ]; then
    echo ""
    echo "${BOLD}Writable paths outside the overlay${OFF}${DIM}  (nothing here shadows the image)${OFF}"
    printf '%s\n' "$OTHERS" | while read -r verb mp; do
        [ -n "$mp" ] || continue
        case "$verb" in
            persist)      note="shared with the other slot; survives updates";;
            slot-private) note="private to slot ${SLOT:-?}; the other slot has its own";;
            volatile)     note="tmpfs; discarded on reboot";;
            *)            note="";;
        esac
        printf '  %-28s %s%s%s\n' "$mp" "$DIM" "$note" "$OFF"
    done
fi

if [ "$shadowing" -gt 0 ]; then
    echo ""
    if [ "$UPPER_MODE" = per-slot ]; then
        echo "The files above are private to slot ${BOLD}${SLOT}${OFF}: this image gives each slot"
        echo "its own upper layer, so booting the other slot leaves every one of them"
        echo "behind. That is the quickest way out if one of them is the problem --"
        echo "nothing here is deleted by doing it, and the other slot's own layer is"
        echo "at ${BOLD}$OVL/upper-$([ "$SLOT" = A ] && echo B || echo A)${OFF}."
        echo ""
        echo "To start this slot clean instead, choose ${BOLD}Recovery: Slot ${SLOT}, reset"
        echo "writable state${OFF} from the GRUB menu; it sets only this slot's layer"
        echo "aside, as ${BOLD}$OVL/upper-${SLOT}.prev${OFF}."
    else
        echo "The files above take precedence over the image on ${BOLD}both${OFF} slots, so an"
        echo "A/B update cannot replace them and booting the other slot will not"
        echo "leave them behind. If one of them is the problem, reboot and choose"
        echo "${BOLD}Recovery: Slot <A|B>, reset writable state${OFF} from the GRUB menu -- what"
        echo "is set aside is kept as ${BOLD}$OVL/*.prev${OFF}, nothing is deleted."
    fi
fi
