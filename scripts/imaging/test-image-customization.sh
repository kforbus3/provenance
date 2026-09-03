#!/bin/bash
# Prove that files you ship in the image beat what the machine already has.
#
# Two things have to be true for "drop a netplan in and it overrides the host"
# to hold, and they fail independently:
#
#   1. the file is in the image at all (overlay.d was copied, script ran)
#   2. it actually wins on a machine that already has its own copy -- the root
#      is an overlay, so the machine's version shadows the image's until the
#      update that delivers yours drops it.
#
# Boot 1: confirm the shipped files are there, then scribble over them the way
#         a person or a config-management tool would.
# Boot 2: same slot -- the machine's own edits must still be there (this is not
#         a system that reverts your changes on every boot).
# Boot 3: other slot, i.e. what an update does -- the image's copies must be
#         back, and a machine-local file the image does NOT own must survive.
#
#   docker run --rm --privileged --platform=linux/amd64 \
#       -v "$PWD/output":/output -v "$PWD/scripts":/s \
#       --entrypoint bash debian-ab-builder:amd64 /s/test-image-customization.sh
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq qemu-system-x86 gdisk util-linux >/dev/null 2>&1

SRC="${SRC:-/output/custom-test.img}"
DISK="${DISK:-/output/custom-target.img}"
SIZE="${SIZE:-32G}"

fail() { echo "HARNESS-FAIL: $*"; exit 1; }
[ -f "$SRC" ] || fail "no $SRC"

# Scratch only; logs carry the evidence (see the runner-disk note in ci.yml).
trap 'rm -f "$DISK"' EXIT
rm -f "$DISK"
truncate -s "$SIZE" "$DISK"
dd if="$SRC" of="$DISK" bs=4M conv=notrunc status=none || fail "dd"

sgdisk -e "$DISK" >/dev/null 2>&1
NUM=$(sgdisk -p "$DISK" 2>/dev/null | awk '$NF == "overlay" { print $1; exit }')
START=$(sgdisk -i "$NUM" "$DISK" 2>/dev/null | awk '/First sector/ { print $3; exit }')
TYPEG=$(sgdisk -i "$NUM" "$DISK" 2>/dev/null | awk '/Partition GUID code/ { print $4; exit }')
UNIQG=$(sgdisk -i "$NUM" "$DISK" 2>/dev/null | awk '/Partition unique GUID/ { print $4; exit }')
sgdisk -d "$NUM" -n "${NUM}:${START}:0" -t "${NUM}:${TYPEG}" \
       -u "${NUM}:${UNIQG}" -c "${NUM}:overlay" "$DISK" >/dev/null 2>&1 || fail "grow"

LO=$(losetup -f --show -P "$DISK") || fail "losetup"
BB=$(basename "$LO")
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    IFS=: read -r mj mn < "/sys/class/block/${BB}p$n/dev"
    rm -f "/dev/${BB}p$n"; mknod "/dev/${BB}p$n" b "$mj" "$mn"
done

# The probe goes in BOTH slots: boot 3 runs the other one, and after an update
# that slot's contents come from the bundle. Here no update happens -- the slot
# switch alone is what exercises the reconciliation -- so both need it.
mkdir -p /mnt/slot
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    mount "/dev/${BB}p$n" /mnt/slot 2>/dev/null || continue
    if [ ! -d /mnt/slot/usr/local/sbin ] || [ ! -d /mnt/slot/etc/systemd/system ]; then
        umount /mnt/slot; continue
    fi
    cat > /mnt/slot/usr/local/sbin/ab-custom-probe.sh <<'PROBE'
#!/bin/sh
exec > /dev/console 2>&1
echo "AB-CUSTOM-PROBE-START"
echo "slot:            $(sed -n 's/.*rauc.slot=\([AB]\).*/\1/p' /proc/cmdline)"
echo "hosts-corp:      $(grep -c corp-fileserver /etc/hosts 2>/dev/null)"
echo "hosts-scribble:  $(grep -c SCRIBBLE /etc/hosts 2>/dev/null)"
echo "netplan:         $(cat /etc/netplan/10-corp.yaml 2>/dev/null | grep -c 'version: 2')"
echo "netplan-scribble:$(grep -c SCRIBBLE /etc/netplan/10-corp.yaml 2>/dev/null)"
echo "machine-own:     $([ -f /etc/netplan/99-machine.yaml ] && echo present || echo absent)"
echo "usr-local-mine:  $([ -f /usr/local/bin/site-script ] && echo present || echo absent)"
echo "usr-local-image: $([ -x /usr/local/sbin/ab-update ] && echo present || echo absent)"
echo "custom-marker:   $([ -f /etc/ab-custom-marker ] && echo present || echo absent)"
echo "owned-list:      $(wc -l < /usr/lib/ab/image-owned.list 2>/dev/null || echo missing)"
if [ ! -f /var/lib/ab-custom-scribbled ]; then
    touch /var/lib/ab-custom-scribbled
    echo "--- scribbling over the image's files, as a person would ---"
    echo "10.9.9.9 SCRIBBLE" >> /etc/hosts
    echo "# SCRIBBLE" >> /etc/netplan/10-corp.yaml
    # A machine-local file the image does NOT own: it must survive the update.
    echo "network: {version: 2}" > /etc/netplan/99-machine.yaml
    # /usr/local is reserved for locally installed software: clearing /usr on a
    # slot change must not take it. The image's own scripts live in
    # /usr/local/sbin, so both have to still be there afterwards.
    mkdir -p /usr/local/bin
    echo "#!/bin/sh" > /usr/local/bin/site-script
    chmod +x /usr/local/bin/site-script
fi
echo "AB-CUSTOM-PROBE-END"
systemctl poweroff --no-block
PROBE
    chmod 0755 /mnt/slot/usr/local/sbin/ab-custom-probe.sh
    cat > /mnt/slot/etc/systemd/system/ab-custom-probe.service <<'UNIT'
[Unit]
Description=Report image-owned file state, then power off
After=multi-user.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ab-custom-probe.sh
[Install]
WantedBy=multi-user.target
UNIT
    mkdir -p /mnt/slot/etc/systemd/system/multi-user.target.wants
    ln -sf /etc/systemd/system/ab-custom-probe.service \
       /mnt/slot/etc/systemd/system/multi-user.target.wants/ab-custom-probe.service
    sync; umount /mnt/slot
done

mkdir -p /mnt/boot
mount "/dev/${BB}p3" /mnt/boot || fail "mount BOOT"
sed -i 's/ quiet//g; s/^set timeout=.*/set timeout=1/' /mnt/boot/grub/grub.cfg
umount /mnt/boot
losetup -d "$LO"

boot() {   # boot <label> <grub default index>
    mount "/dev/$(basename "$(losetup -f --show -P "$DISK")")p3" /mnt/boot 2>/dev/null || true
    LO=$(losetup -j "$DISK" | cut -d: -f1 | head -1); BB=$(basename "$LO")
    for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
        IFS=: read -r mj mn < "/sys/class/block/${BB}p$n/dev"
        rm -f "/dev/${BB}p$n"; mknod "/dev/${BB}p$n" b "$mj" "$mn" 2>/dev/null || true
    done
    umount /mnt/boot 2>/dev/null || true
    mount "/dev/${BB}p3" /mnt/boot
    sed -i "/^# --- recovery/i set default=$2" /mnt/boot/grub/grub.cfg
    umount /mnt/boot
    losetup -d "$LO" 2>/dev/null || true

    echo ""
    echo "=== boot: $1 (slot index $2) ==="
    timeout "${BOOT_TIMEOUT:-420}" qemu-system-x86_64 -m 2048 -smp 2 \
        -drive file="$DISK",format=raw,if=virtio \
        -nographic -serial mon:stdio -no-reboot > "/output/custom-$1.log" 2>&1
    sed -n '/AB-CUSTOM-PROBE-START/,/AB-CUSTOM-PROBE-END/p' "/output/custom-$1.log" \
        | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' | sed 's/^/  /'

    LO=$(losetup -f --show -P "$DISK"); BB=$(basename "$LO")
    for n in 3; do
        IFS=: read -r mj mn < "/sys/class/block/${BB}p$n/dev"
        rm -f "/dev/${BB}p$n"; mknod "/dev/${BB}p$n" b "$mj" "$mn"
    done
    mount "/dev/${BB}p3" /mnt/boot
    sed -i "/^set default=$2$/d" /mnt/boot/grub/grub.cfg
    umount /mnt/boot
    losetup -d "$LO"
}

boot shipped 0        # image files present; then scribble over them
boot same-slot 0      # the machine's own edits survive an ordinary reboot
boot other-slot 1     # what an update does: the image's copies come back

echo ""
echo "=== result ==="
ok=1
grep -qa "hosts-corp:      1" /output/custom-shipped.log || { echo "  FAIL: /etc/hosts was not shipped"; ok=0; }
grep -qa "custom-marker:   present" /output/custom-shipped.log || { echo "  FAIL: --run-script did not run"; ok=0; }
grep -qa "hosts-scribble:  1" /output/custom-same-slot.log || { echo "  FAIL: the machine's own edit did not survive a plain reboot"; ok=0; }
grep -qa "hosts-scribble:  0" /output/custom-other-slot.log || { echo "  FAIL: the image did not win after the slot change"; ok=0; }
grep -qa "netplan-scribble:0" /output/custom-other-slot.log || { echo "  FAIL: the netplan the image owns was not restored"; ok=0; }
grep -qa "machine-own:     present" /output/custom-other-slot.log || { echo "  FAIL: a machine-local file was destroyed; only owned paths may be dropped"; ok=0; }
grep -qa "usr-local-mine:  present" /output/custom-other-slot.log || { echo "  FAIL: /usr/local was cleared with /usr; locally installed software must survive"; ok=0; }
grep -qa "usr-local-image: present" /output/custom-other-slot.log || { echo "  FAIL: the image's own /usr/local/sbin tools went missing after the slot change"; ok=0; }
[ "$ok" = 1 ] && echo "  PASS: image-owned files override the machine, machine-local files survive" || exit 1
