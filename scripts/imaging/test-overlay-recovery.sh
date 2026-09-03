#!/bin/bash
# Prove the recovery path end to end, by booting it.
#
# Boot 1 (normal)   : change a file that came from the image, and add one that
#                     did not. This is the state a person gets into by using the
#                     machine, and the reason booting the other slot does not by
#                     itself undo anything.
# Boot 2 (recovery) : the "reset overlay" GRUB entry. The image's file must be
#                     back to its original contents, the added file must be gone
#                     from /, and both must still exist under upper.prev --
#                     because the whole promise is that nothing is deleted.
#
# Run it against an image built into ./output:
#
#   docker run --rm --privileged --platform=linux/amd64 \
#       -v "$PWD/output":/output -v "$PWD/scripts":/s \
#       --entrypoint bash debian-ab-builder:amd64 /s/test-overlay-recovery.sh
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq qemu-system-x86 gdisk cryptsetup-bin util-linux >/dev/null 2>&1

SRC="${SRC:-/output/ovl-test.img}"
DISK="${DISK:-/output/recovery-target.img}"
PASS="${PASS:-testluks}"
SIZE="${SIZE:-32G}"
MARKER=/root/ab-added-by-hand      # a file the image never had
SHADOW=/etc/ab-shadow-test         # a file the image ships, changed here

fail() { echo "HARNESS-FAIL: $*"; exit 1; }
[ -f "$SRC" ] || fail "no $SRC"

rm -f "$DISK"
truncate -s "$SIZE" "$DISK"
# Scratch only; logs carry the evidence. Suite tests leaving their ~8 GB
# disks behind filled the CI runner mid-suite (2026-08-16).
trap 'rm -f "$DISK"' EXIT
dd if="$SRC" of="$DISK" bs=4M conv=notrunc status=none || fail "dd"

# --- the imager's post-write steps -------------------------------------------
sgdisk -e "$DISK" >/dev/null 2>&1
NUM=$(sgdisk -p "$DISK" 2>/dev/null | awk '$NF == "overlay" { print $1; exit }')
[ -n "$NUM" ] || fail "no overlay partition"
START=$(sgdisk -i "$NUM" "$DISK" 2>/dev/null | awk '/First sector/ { print $3; exit }')
TYPEG=$(sgdisk -i "$NUM" "$DISK" 2>/dev/null | awk '/Partition GUID code/ { print $4; exit }')
UNIQG=$(sgdisk -i "$NUM" "$DISK" 2>/dev/null | awk '/Partition unique GUID/ { print $4; exit }')
sgdisk -d "$NUM" -n "${NUM}:${START}:0" -t "${NUM}:${TYPEG}" \
       -u "${NUM}:${UNIQG}" -c "${NUM}:overlay" "$DISK" >/dev/null 2>&1 || fail "grow"

LO=$(losetup -f --show -P "$DISK") || fail "losetup"
BB=$(basename "$LO")
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    IFS=: read -r mj mn < "/sys/class/block/${BB}p$n/dev"
    rm -f "/dev/${BB}p$n"; mknod "/dev/${BB}p$n" b "$mj" "$mn" || fail "mknod p$n"
done

# --- find the BOOT partition (grub.cfg) and a root slot ----------------------
BOOTP=""; ROOTP=""
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    if debugfs -R "ls /grub" "/dev/${BB}p$n" 2>/dev/null | grep -q grub.cfg; then BOOTP="$n"; fi
done
[ -n "$BOOTP" ] || fail "no BOOT partition"

mkdir -p /mnt/slot /mnt/boot
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    DEV="/dev/${BB}p$n"
    if cryptsetup isLuks "$DEV" 2>/dev/null; then
        printf '%s' "$PASS" | cryptsetup open "$DEV" rec-root - 2>/dev/null || continue
        M=/dev/mapper/rec-root
    else
        M="$DEV"
    fi
    if mount "$M" /mnt/slot 2>/dev/null; then
        if [ -d /mnt/slot/etc/systemd/system ] && [ -d /mnt/slot/usr/local/sbin ]; then
            ROOTP="$n"; break
        fi
        umount /mnt/slot
    fi
    cryptsetup close rec-root 2>/dev/null || true
done
[ -n "$ROOTP" ] || fail "no root slot"

# The file the image ships, so boot 1 can shadow something real.
echo "from-the-image" > "/mnt/slot${SHADOW}"

cat > /mnt/slot/usr/local/sbin/ab-recovery-probe.sh <<PROBE
#!/bin/sh
exec > /dev/console 2>&1
echo "AB-PROBE-START"
echo "root-fstype:  \$(findmnt -no FSTYPE / 2>/dev/null)"
echo "shadow-file:  \$(cat ${SHADOW} 2>/dev/null || echo MISSING)"
echo "added-file:   \$([ -e ${MARKER} ] && echo present || echo absent)"
echo "upper.prev:   \$([ -d /var/lib/overlay/upper.prev ] && echo present || echo absent)"
if [ -d /var/lib/overlay/upper.prev ]; then
    echo "prev-shadow:  \$(cat /var/lib/overlay/upper.prev${SHADOW} 2>/dev/null || echo MISSING)"
    echo "prev-added:   \$([ -e /var/lib/overlay/upper.prev${MARKER} ] && echo present || echo absent)"
fi
if [ ! -e ${MARKER} ] && [ ! -d /var/lib/overlay/upper.prev ]; then
    echo "--- first boot: making changes a person would make ---"
    echo "changed-on-this-machine" > ${SHADOW}
    echo "hello" > ${MARKER}
    echo "wrote ${SHADOW} and ${MARKER}"
fi
echo "--- ab-overlay-diff ---"
/usr/local/sbin/ab-overlay-diff 2>&1 | head -20
echo "AB-PROBE-END"
systemctl poweroff --no-block
PROBE
chmod 0755 /mnt/slot/usr/local/sbin/ab-recovery-probe.sh

cat > /mnt/slot/etc/systemd/system/ab-recovery-probe.service <<'UNIT'
[Unit]
Description=Report overlay recovery state to the console, then power off
After=multi-user.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ab-recovery-probe.sh
[Install]
WantedBy=multi-user.target
UNIT
mkdir -p /mnt/slot/etc/systemd/system/multi-user.target.wants
ln -sf /etc/systemd/system/ab-recovery-probe.service \
   /mnt/slot/etc/systemd/system/multi-user.target.wants/ab-recovery-probe.service
sync; umount /mnt/slot; cryptsetup close rec-root 2>/dev/null || true

boot() {   # boot <label> <grub-default-index>
    mount "/dev/${BB}p${BOOTP}" /mnt/boot || fail "mount BOOT"
    sed -i 's/ quiet//g; s/^set timeout=.*/set timeout=1/' /mnt/boot/grub/grub.cfg
    sed -i '/^# --- recovery/i set default='"$2"'' /mnt/boot/grub/grub.cfg
    # The try-counter block above assigns default; this line comes after it and
    # before the menuentries, so it wins -- which is what choosing at the menu
    # does. Remove any line left from a previous boot first.
    grep -c "^set default=$2" /mnt/boot/grub/grub.cfg >/dev/null
    umount /mnt/boot
    echo ""
    echo "=== boot: $1 (menu index $2) ==="
    timeout 420 qemu-system-x86_64 -m 2048 -smp 2 \
        -drive file="$DISK",format=raw,if=virtio \
        -nographic -serial mon:stdio -no-reboot > "/output/recovery-$1.log" 2>&1
    sed -n '/AB-PROBE-START/,/AB-PROBE-END/p' "/output/recovery-$1.log" | sed 's/^/  /'
    grep -a "ab-overlay:" "/output/recovery-$1.log" | tail -3 | sed 's/^/  /'
    # Undo the injected default so the next boot starts from a clean grub.cfg.
    mount "/dev/${BB}p${BOOTP}" /mnt/boot
    sed -i "/^set default=$2$/d" /mnt/boot/grub/grub.cfg
    umount /mnt/boot
}

losetup -d "$LO" 2>/dev/null || true
LO=$(losetup -f --show -P "$DISK"); BB=$(basename "$LO")
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    IFS=: read -r mj mn < "/sys/class/block/${BB}p$n/dev"
    rm -f "/dev/${BB}p$n"; mknod "/dev/${BB}p$n" b "$mj" "$mn"
done

boot first-boot 0        # makes the changes
boot second-boot 0       # they are still there -- the behaviour that prompted this
boot recovery-reset 2    # and now they are not, but nothing was destroyed

losetup -d "$LO" 2>/dev/null || true

echo ""
echo "=== what to expect ==="
echo "  first-boot:      shadow-file=from-the-image, added-file=absent"
echo "                   (then it makes the changes)"
echo "  second-boot:     shadow-file=changed-on-this-machine, added-file=present"
echo "                   and ab-overlay-diff reports 1 file shadowing the image"
echo "  recovery-reset:  shadow-file=from-the-image, added-file=absent,"
echo "                   upper.prev=present, prev-added=present"
