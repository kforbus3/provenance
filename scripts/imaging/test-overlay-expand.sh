#!/bin/bash
# Overlay expansion test. Runs in a privileged container, no QEMU needed:
#
#   docker run --rm --privileged --platform linux/amd64 \
#     -v "$PWD":/repo:ro ubuntu:22.04 bash /repo/scripts/test-overlay-expand.sh
#
# SKIP_IMAGER_GROW=1  simulate an imager that does not grow the partition
# KEEP_KEY=1          leave a usable LUKS keyfile in crypttab
#
# The combination that used to strand a machine forever is SKIP_IMAGER_GROW=1
# with no key: the partition was never grown, and by first boot enrolment had
# consumed the keyfile, so `cryptsetup resize` had nothing to work with. The
# imager growing the partition is what makes that state unreachable.
#
#   1. build an 11G image with the real partition layout and an encrypted overlay
#   2. write it to a 32G disk, exactly as the imager does
#   3. run the imager's post-write steps (sgdisk -e, grow the overlay)
#   4. open the overlay and run first-boot-expand.sh, with NO keyfile available
#
# Step 4 is the point: after the imager grows the partition, expansion must
# complete without a key, which is the condition that made it fail before.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq gdisk cryptsetup-bin cloud-guest-utils e2fsprogs util-linux >/dev/null 2>&1

fail() { echo "SETUP FAILED: $*"; exit 1; }
nodes() {   # make partition device nodes; a container has no udev
    local base="$1" n sys maj min
    for n in 1 2 3 4 5 6; do
        sys="/sys/class/block/${base}p${n}/dev"
        [ -r "$sys" ] || continue
        IFS=: read -r maj min < "$sys"
        rm -f "/dev/${base}p${n}"
        mknod "/dev/${base}p${n}" b "$maj" "$min" 2>/dev/null || true
    done
}

# ---- 1. the image, as the builder produces it -------------------------------
IMG=/tmp/image.img
truncate -s 11G "$IMG"
sgdisk -n1:2048:+1M -t1:EF02 -c1:bios \
       -n2:0:+128M  -t2:EF00 -c2:EFI \
       -n3:0:+512M  -t3:8300 -c3:BOOT \
       -n4:0:+5G    -t4:8300 -c4:rootfs-a \
       -n5:0:+5G    -t5:8300 -c5:rootfs-b \
       -n6:0:+256M  -t6:8300 -c6:overlay "$IMG" >/dev/null

ILOOP=$(losetup -f --show -P "$IMG") || fail losetup
nodes "$(basename "$ILOOP")"
KEY=/tmp/build.key
head -c 64 /dev/urandom > "$KEY"
cryptsetup luksFormat --type luks2 --batch-mode "${ILOOP}p6" "$KEY" >/dev/null 2>&1 || fail luksFormat
cryptsetup open --key-file "$KEY" "${ILOOP}p6" build-ovl || fail luksOpen
mkfs.ext4 -q -L overlay /dev/mapper/build-ovl || fail mkfs
cryptsetup close build-ovl
losetup -d "$ILOOP"

# ---- 2. write it to a 32G disk ---------------------------------------------
DISK=/tmp/target.img
truncate -s 32G "$DISK"
dd if="$IMG" of="$DISK" bs=4M conv=notrunc status=none

TARGET=$(losetup -f --show -P "$DISK") || fail losetup
nodes "$(basename "$TARGET")"
echo "=== as imaged: the GPT still describes an 11G disk ==="
sgdisk -p "$TARGET" 2>/dev/null | grep -E "last usable|^ +6" | sed 's/^/  /'

# ---- 3. the imager's post-write steps --------------------------------------
echo ""
echo "=== imager: relocate GPT backup header, then grow the overlay ==="
sgdisk -e "$TARGET" >/dev/null 2>&1
NUM=$(sgdisk -p "$TARGET" 2>/dev/null | awk '$NF == "overlay" { print $1; exit }')
START=$(sgdisk -i "$NUM" "$TARGET" 2>/dev/null | awk '/First sector/ { print $3; exit }')
TYPEG=$(sgdisk -i "$NUM" "$TARGET" 2>/dev/null | awk '/Partition GUID code/ { print $4; exit }')
UNIQG=$(sgdisk -i "$NUM" "$TARGET" 2>/dev/null | awk '/Partition unique GUID/ { print $4; exit }')
echo "  overlay=partition $NUM start=$START"
if [ "${SKIP_IMAGER_GROW:-0}" = 1 ]; then
    echo "  (skipping imager growth: simulating an older imager)"
else
    sgdisk -d "$NUM" -n "${NUM}:${START}:0" -t "${NUM}:${TYPEG}" \
           -u "${NUM}:${UNIQG}" -c "${NUM}:overlay" "$TARGET" >/dev/null 2>&1 || fail "sgdisk grow"
fi
blockdev --rereadpt "$TARGET" 2>/dev/null || true
losetup -d "$TARGET"; sleep 1
TARGET=$(losetup -f --show -P "$DISK"); sleep 1; nodes "$(basename "$TARGET")"
sgdisk -p "$TARGET" 2>/dev/null | grep -E "^ +6" | sed 's/^/  /'

# ---- 4. first boot, with NO keyfile ----------------------------------------
echo ""
echo "=== first boot: open the overlay, keyfile deliberately absent ==="
cryptsetup open --key-file "$KEY" "${TARGET}p6" luks-overlay || fail "luksOpen at boot"
if [ "${KEEP_KEY:-0}" = 1 ]; then
    printf 'luks-overlay %sp6 %s luks\n' "$TARGET" "$KEY" > /etc/crypttab
else
    rm -f "$KEY"                 # as LUKS enrolment would have done
    printf 'luks-overlay %sp6 none luks\n' "$TARGET" > /etc/crypttab
fi
mkdir -p /var/lib/overlay
mount /dev/mapper/luks-overlay /var/lib/overlay || fail mount

BEFORE=$(df -B1 --output=size /var/lib/overlay | tail -1 | tr -d ' ')
echo "  overlay filesystem before: $(numfmt --to=iec "$BEFORE")"
echo ""
"${REPO:-/repo}"/builder/overlay/usr/local/sbin/first-boot-expand.sh 2>&1 | sed 's/^/  /'

AFTER=$(df -B1 --output=size /var/lib/overlay | tail -1 | tr -d ' ')
echo ""
echo "=== result ==="
df -h /var/lib/overlay | tail -1 | sed 's/^/  /'
echo "  stamp: $([ -f /var/lib/first-boot-expand.done ] && echo present || echo absent)"
if [ "$AFTER" -gt $((20 * 1024 * 1024 * 1024)) ]; then
    echo "  PASS: overlay grew to $(numfmt --to=iec "$AFTER") with no keyfile present"
else
    echo "  FAIL: overlay is $(numfmt --to=iec "$AFTER"), expected >20G"
fi

umount /var/lib/overlay 2>/dev/null
cryptsetup close luks-overlay 2>/dev/null
losetup -d "$TARGET" 2>/dev/null
