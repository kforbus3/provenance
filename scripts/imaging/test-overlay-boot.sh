#!/bin/bash
# Boot a written image on a disk larger than the image and report, from inside
# the booted system, whether / is an overlay and how much space /home has.
#
# The question this answers is the one that started all of it: a user writing to
# /home must get the whole disk, not the root slot. Two earlier attempts at this
# were called fixed on the strength of code inspection and were not, so nothing
# here is inferred -- the probe runs in the booted machine and prints df.
#
# Run it against an image built into ./output:
#
#   docker run --rm --privileged --platform=linux/amd64 \
#       -v "$PWD/output":/output -v "$PWD/scripts":/s \
#       --entrypoint bash debian-ab-builder:amd64 /s/test-overlay-boot.sh
#
# Works on encrypted and unencrypted images; PASS is only needed for the former.
# Expect: "root is now an overlay", root-fstype overlay, and /home sized to the
# disk rather than to the ~3G root slot.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq qemu-system-x86 gdisk cryptsetup-bin util-linux >/dev/null 2>&1

SRC="${SRC:-/output/ovl-test.img}"      # image to test
DISK="${DISK:-/output/boot-target.img}"  # scratch target, recreated each run
PASS="${PASS:-testluks}"                 # --luks-passphrase used at build time
SIZE="${SIZE:-32G}"                      # target disk, deliberately > the image
BOOT_TIMEOUT="${BOOT_TIMEOUT:-360}"      # seconds; raise it when QEMU has no KVM
                                         # (an x86 guest on an arm64 host is pure TCG
                                         #  and takes several times longer to boot)

fail() { echo "HARNESS-FAIL: $*"; exit 1; }

[ -f "$SRC" ] || fail "no $SRC"

rm -f "$DISK"
truncate -s "$SIZE" "$DISK"
dd if="$SRC" of="$DISK" bs=4M conv=notrunc status=none || fail "dd"

# --- the imager's post-write steps -------------------------------------------
sgdisk -e "$DISK" >/dev/null 2>&1
NUM=$(sgdisk -p "$DISK" 2>/dev/null | awk '$NF == "overlay" { print $1; exit }')
[ -n "$NUM" ] || fail "no overlay partition found"
START=$(sgdisk -i "$NUM" "$DISK" 2>/dev/null | awk '/First sector/ { print $3; exit }')
TYPEG=$(sgdisk -i "$NUM" "$DISK" 2>/dev/null | awk '/Partition GUID code/ { print $4; exit }')
UNIQG=$(sgdisk -i "$NUM" "$DISK" 2>/dev/null | awk '/Partition unique GUID/ { print $4; exit }')
sgdisk -d "$NUM" -n "${NUM}:${START}:0" -t "${NUM}:${TYPEG}" \
       -u "${NUM}:${UNIQG}" -c "${NUM}:overlay" "$DISK" >/dev/null 2>&1 || fail "grow"

echo "=== partition table after the imager step ==="
sgdisk -p "$DISK" 2>/dev/null | sed -n '/Number/,$p' | sed 's/^/  /'

# --- attach, and give the loop device real partition nodes -------------------
LO=$(losetup -f --show -P "$DISK") || fail "losetup"
BB=$(basename "$LO")
mknode() {  # mknode <partnum>
    local sy=/sys/class/block/${BB}p$1/dev mj mn
    [ -r "$sy" ] || fail "no sysfs entry for partition $1"
    IFS=: read -r mj mn < "$sy"
    rm -f "/dev/${BB}p$1"
    mknod "/dev/${BB}p$1" b "$mj" "$mn" || fail "mknod p$1"
}
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do mknode "$n"; done

cleanup() {
    umount /mnt/slot 2>/dev/null || true
    cryptsetup close verify-root 2>/dev/null || true
    losetup -d "$LO" 2>/dev/null || true
}
trap cleanup EXIT

# --- drop `quiet` so the initramfs stage is visible ---------------------------
BOOTP=$(for n in 1 2 3 4 5 6; do
            [ -b "/dev/${BB}p$n" ] || continue
            blkid -s TYPE -o value "/dev/${BB}p$n" 2>/dev/null | grep -q ext && \
              debugfs -R "ls /grub" "/dev/${BB}p$n" 2>/dev/null | grep -q grub.cfg && { echo "$n"; break; }
        done)
if [ -n "$BOOTP" ]; then
    mkdir -p /mnt/boot && mount "/dev/${BB}p${BOOTP}" /mnt/boot 2>/dev/null && {
        sed -i 's/ quiet//g' /mnt/boot/grub/grub.cfg 2>/dev/null || true
        umount /mnt/boot
        echo "  removed 'quiet' from grub.cfg on partition $BOOTP"
    }
fi

# --- install a probe into slot A ---------------------------------------------
# The slot is LUKS, so it is opened with the build passphrase. The probe runs
# late in boot, prints what it finds to the console, and powers the machine off,
# so the harness needs no login and cannot hang waiting at one.
ROOTA=""
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    DEV="/dev/${BB}p$n"
    mkdir -p /mnt/slot
    if cryptsetup isLuks "$DEV" 2>/dev/null; then
        printf '%s' "$PASS" | cryptsetup open "$DEV" verify-root - 2>/dev/null || continue
        MNTDEV=/dev/mapper/verify-root
    else
        MNTDEV="$DEV"
    fi
    if mount "$MNTDEV" /mnt/slot 2>/dev/null; then
        if [ -d /mnt/slot/etc/systemd/system ] && [ -d /mnt/slot/usr/local/sbin ]; then
            ROOTA="$n"; break
        fi
        umount /mnt/slot
    fi
    cryptsetup close verify-root 2>/dev/null || true
done
[ -n "$ROOTA" ] || fail "could not open a root slot to install the probe"
echo "  probe installed into the root slot on partition $ROOTA"

cat > /mnt/slot/usr/local/sbin/ab-verify.sh <<'PROBE'
#!/bin/sh
exec > /dev/console 2>&1
echo "AB-VERIFY-START"
echo "root-fstype: $(findmnt -no FSTYPE / 2>/dev/null)"
echo "root-source: $(findmnt -no SOURCE / 2>/dev/null)"
echo "--- df ---"
df -h / /home /var/lib/overlay 2>/dev/null
echo "--- mount lines ---"
grep -E ' / | /var/lib/overlay ' /proc/mounts 2>/dev/null
echo "--- write test into /home ---"
if dd if=/dev/zero of=/home/.abtest bs=1M count=64 2>/dev/null; then
    echo "wrote 64M to /home ok; /home avail now: $(df -h /home | awk 'NR==2{print $4}')"
    rm -f /home/.abtest
else
    echo "could not write 64M to /home"
fi
echo "AB-VERIFY-END"
systemctl poweroff --no-block
PROBE
chmod 0755 /mnt/slot/usr/local/sbin/ab-verify.sh

cat > /mnt/slot/etc/systemd/system/ab-verify.service <<'UNIT'
[Unit]
Description=Report the root/overlay layout to the console, then power off
After=multi-user.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ab-verify.sh
[Install]
WantedBy=multi-user.target
UNIT
mkdir -p /mnt/slot/etc/systemd/system/multi-user.target.wants
ln -sf /etc/systemd/system/ab-verify.service \
   /mnt/slot/etc/systemd/system/multi-user.target.wants/ab-verify.service

sync
umount /mnt/slot
cryptsetup close verify-root 2>/dev/null || true
losetup -d "$LO"
# Loop work is done; keep a disk-removal trap armed for the boot phase. The
# scratch disk is ~8 GB and every suite test leaving one behind filled the CI
# runner mid-suite (2026-08-16). The evidence a failure needs is the logs.
trap 'rm -f "$DISK"' EXIT

# --- boot ---------------------------------------------------------------------
echo ""
echo "=== booting (up to ${BOOT_TIMEOUT}s) ==="
timeout "$BOOT_TIMEOUT" qemu-system-x86_64 -m 2048 -smp 2 \
    -drive file="$DISK",format=raw,if=virtio \
    -nographic -serial mon:stdio -no-reboot > /output/bootcheck.log 2>&1

echo ""
echo "=== ab-overlay lines from the initramfs ==="
grep -a "ab-overlay" /output/bootcheck.log | sed 's/^/  /' || echo "  (none)"
echo ""
echo "=== probe output ==="
sed -n '/AB-VERIFY-START/,/AB-VERIFY-END/p' /output/bootcheck.log | sed 's/^/  /' \
    || echo "  (probe never ran)"
echo ""
if ! grep -qa AB-VERIFY-START /output/bootcheck.log; then
    echo "=== probe did not run; tail of the boot log ==="
    tail -40 /output/bootcheck.log | sed 's/^/  /'
fi
