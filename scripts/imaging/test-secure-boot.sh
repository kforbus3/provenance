#!/bin/bash
# Boot a built image under firmware that is actually enforcing Secure Boot.
#
# "Secure Boot support" is the easiest claim in this project to make falsely.
# An image with shim on its ESP boots perfectly on firmware with Secure Boot
# switched off, and so does one without — so a test that only proves the image
# boots proves nothing at all about Secure Boot. Three runs are needed:
#
#   1. enforcing firmware, image as built     -> must boot, and the kernel must
#                                                agree that Secure Boot is on
#   2. enforcing firmware, BOOTX64.EFI damaged -> must NOT boot. This is the
#                                                control: without it, run 1
#                                                passing could just mean the
#                                                firmware was not enforcing.
#   3. firmware with Secure Boot off           -> must boot. A Secure Boot image
#                                                that only works with Secure
#                                                Boot on would be a regression
#                                                for every machine that has it
#                                                disabled.
#
#   docker run --rm --privileged --platform=linux/amd64 \
#       -v "$PWD/output":/output -v "$PWD/scripts":/s \
#       --entrypoint bash debian-ab-builder:amd64 /s/test-secure-boot.sh
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq qemu-system-x86 ovmf gdisk dosfstools mtools util-linux \
    >/dev/null 2>&1

SRC="${SRC:-/output/sb-test.img}"
DISK="${DISK:-/output/sb-target.img}"
SIZE="${SIZE:-16G}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-420}"
# A refusal is fast: the firmware decides before it ever runs anything. Waiting
# the full boot timeout to conclude "it did not boot" would add ten minutes to
# every run for the one case that is quickest to decide.
DENY_TIMEOUT="${DENY_TIMEOUT:-120}"

fail() { echo "HARNESS-FAIL: $*"; exit 1; }
ok=0; bad=0
pass() { ok=$((ok+1)); echo "  PASS  $1"; }
no()   { bad=$((bad+1)); echo "  FAIL  $1 ${2:-}"; }

[ -f "$SRC" ] || fail "no $SRC — build one with --secure-boot on"

# --- firmware ----------------------------------------------------------------
#
# The .secboot code image is the one that enforces; the .ms vars have
# Microsoft's keys enrolled, which is what a shipped machine has. Both are in
# Debian's ovmf package. Without them there is nothing to test against and
# saying so is the only honest outcome.
FW_DIR=/usr/share/OVMF
CODE_SB=""; VARS_MS=""; CODE_PLAIN=""; VARS_PLAIN=""
for f in "$FW_DIR/OVMF_CODE_4M.secboot.fd" "$FW_DIR/OVMF_CODE.secboot.fd"; do
    [ -f "$f" ] && { CODE_SB="$f"; break; }
done
for f in "$FW_DIR/OVMF_VARS_4M.ms.fd" "$FW_DIR/OVMF_VARS.ms.fd"; do
    [ -f "$f" ] && { VARS_MS="$f"; break; }
done
for f in "$FW_DIR/OVMF_CODE_4M.fd" "$FW_DIR/OVMF_CODE.fd"; do
    [ -f "$f" ] && { CODE_PLAIN="$f"; break; }
done
for f in "$FW_DIR/OVMF_VARS_4M.fd" "$FW_DIR/OVMF_VARS.fd"; do
    [ -f "$f" ] && { VARS_PLAIN="$f"; break; }
done
[ -n "$CODE_SB" ] && [ -n "$VARS_MS" ] \
    || fail "this ovmf has no Secure Boot firmware with Microsoft keys enrolled
    (looked for OVMF_CODE_4M.secboot.fd and OVMF_VARS_4M.ms.fd in $FW_DIR).
    Without them nothing here would be testing Secure Boot."

# --- the disk ----------------------------------------------------------------
rm -f "$DISK"
truncate -s "$SIZE" "$DISK"
dd if="$SRC" of="$DISK" bs=4M conv=notrunc status=none || fail "dd"
sgdisk -e "$DISK" >/dev/null 2>&1
trap 'rm -f "$DISK" /tmp/vars-*.fd' EXIT

esp_offset() {   # byte offset of the ESP, for mtools
    local num start
    num=$(sgdisk -p "$DISK" 2>/dev/null | awk '$NF == "ESP" { print $1; exit }')
    [ -n "$num" ] || return 1
    start=$(sgdisk -i "$num" "$DISK" 2>/dev/null | awk '/First sector/ { print $3; exit }')
    [ -n "$start" ] || return 1
    echo $((start * 512))
}
OFF="$(esp_offset)" || fail "no ESP partition on $DISK"
export MTOOLS_SKIP_CHECK=1
mt() { mtools -c "$@" -i "$DISK@@$OFF"; }

echo "=== what is on the ESP ==="
mt mdir -/ ::/EFI 2>/dev/null | sed 's/^/  /' || echo "  (unreadable)"

for want in ::/EFI/BOOT/BOOTX64.EFI ::/EFI/BOOT/grubx64.efi; do
    if mt mtype "$want" >/dev/null 2>&1; then
        pass "the ESP carries $(basename "$want")"
    else
        no "the ESP carries $(basename "$want")" "(not found)"
    fi
done
# The stub the distribution's signed GRUB will look for. Its prefix is compiled
# into a binary this build does not produce, so if this is missing the machine
# reaches a GRUB rescue prompt rather than a boot menu -- with Secure Boot
# working perfectly, which makes it a confusing way to fail.
if mt mtype ::/EFI/debian/grub.cfg >/dev/null 2>&1 \
   || mt mtype ::/EFI/ubuntu/grub.cfg >/dev/null 2>&1; then
    pass "the prefix stub GRUB looks for is present"
else
    no "the prefix stub GRUB looks for is present" "(no /EFI/*/grub.cfg)"
fi

# --- a probe inside the machine ----------------------------------------------
#
# The firmware's own word for whether Secure Boot was enforcing, read from the
# EFI variable rather than from the kernel log. The first version of this test
# grepped the boot log for "Secure boot enabled" and failed against a machine
# that had booted perfectly under enforcing firmware -- the images boot with
# `quiet`, which suppresses exactly that line. Asking the running system is both
# authoritative and independent of how noisy the kernel was told to be.
#
# The probe powers the machine off when it is done, so a run ends in seconds
# rather than sitting at a login prompt until the timeout.
LO=$(losetup -f --show -P "$DISK") || fail "losetup"
BB=$(basename "$LO")
part_node() {   # part_node <number> -> device path, creating the node if needed
    local n="$1" node="/dev/${BB}p$1" mj mn
    if [ ! -b "$node" ]; then
        # Loop partition nodes are not created inside a container; make them by
        # hand from what the kernel already knows.
        [ -e "/sys/class/block/${BB}p${n}/dev" ] || return 1
        IFS=: read -r mj mn < "/sys/class/block/${BB}p${n}/dev"
        rm -f "$node"; mknod "$node" b "$mj" "$mn" || return 1
    fi
    echo "$node"
}
ROOTNUM=$(sgdisk -p "$DISK" 2>/dev/null | awk '$NF == "rootfs-a" { print $1; exit }')
[ -n "$ROOTNUM" ] || { losetup -d "$LO"; fail "no rootfs-a partition on $DISK"; }
ROOTDEV=$(part_node "$ROOTNUM") || { losetup -d "$LO"; fail "no node for partition $ROOTNUM"; }
mkdir -p /mnt/sbslot
mount "$ROOTDEV" /mnt/sbslot || { losetup -d "$LO"; fail "could not mount the root slot"; }

cat > /mnt/sbslot/usr/local/sbin/sb-probe.sh <<'PROBE'
#!/bin/sh
exec > /dev/console 2>&1
echo "SB-PROBE-START"
# efivarfs: the first four bytes are the variable's attributes, the fifth is the
# value. systemd mounts this automatically on an EFI boot; if it is not there,
# the machine did not boot via UEFI at all, which is itself worth saying.
VAR=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
if [ ! -d /sys/firmware/efi ]; then
    echo "secure-boot: no-efi"
elif [ -r "$VAR" ]; then
    echo "secure-boot: $(od -An -t u1 -j 4 -N 1 "$VAR" 2>/dev/null | tr -d ' ')"
else
    # The firmware build without Secure Boot support does not define the
    # variable at all. Absent is a real answer and not the same as zero.
    echo "secure-boot: absent"
fi
echo "SB-PROBE-END"
systemctl poweroff --no-block
PROBE
chmod 0755 /mnt/sbslot/usr/local/sbin/sb-probe.sh

cat > /mnt/sbslot/etc/systemd/system/sb-probe.service <<'UNIT'
[Unit]
Description=Report the firmware's Secure Boot state to the console, then power off
After=multi-user.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sb-probe.sh
[Install]
WantedBy=multi-user.target
UNIT
mkdir -p /mnt/sbslot/etc/systemd/system/multi-user.target.wants
ln -sf /etc/systemd/system/sb-probe.service \
   /mnt/sbslot/etc/systemd/system/multi-user.target.wants/sb-probe.service
sync
umount /mnt/sbslot
losetup -d "$LO"
echo "  probe installed into rootfs-a (partition $ROOTNUM)"

sb_state() {   # sb_state <logfile> -> the probe's answer, or empty
    sed -n 's/^ *secure-boot: *//p' "$1" 2>/dev/null | tr -d '\r' | head -1
}

boot() {   # boot <label> <code.fd> <vars.fd> <timeout> <logfile>
    cp "$3" "/tmp/vars-$1.fd"
    echo ""
    echo "=== $1 (up to ${4}s) ==="
    timeout "$4" qemu-system-x86_64 \
        -machine q35,smm=on -m 2048 -smp 2 \
        -global driver=cfi.pflash01,property=secure,value=on \
        -drive if=pflash,format=raw,unit=0,readonly=on,file="$2" \
        -drive if=pflash,format=raw,unit=1,file="/tmp/vars-$1.fd" \
        -drive file="$DISK",format=raw,if=virtio \
        -nographic -serial mon:stdio -no-reboot > "$5" 2>&1
    return 0
}

# --- 1. enforcing firmware, image as built -----------------------------------
boot enforcing "$CODE_SB" "$VARS_MS" "$BOOT_TIMEOUT" /output/sb-enforcing.log
if grep -qa "SB-PROBE-START" /output/sb-enforcing.log; then
    pass "the image boots with Secure Boot enforcing"
else
    no "the image boots with Secure Boot enforcing" "(see /output/sb-enforcing.log)"
    tail -30 /output/sb-enforcing.log | sed 's/^/      /'
fi
# The firmware's own word for it, read from the EFI variable inside the booted
# machine. Without this the run above only proves it booted, which it would also
# do on firmware that had quietly fallen back to no verification.
state="$(sb_state /output/sb-enforcing.log)"
if [ "$state" = "1" ]; then
    pass "and the firmware reports Secure Boot as enforcing"
else
    no "and the firmware reports Secure Boot as enforcing" "(probe said '${state:-nothing}')"
fi

# --- 2. the control: a damaged loader must be refused ------------------------
#
# Everything above passes on firmware that is not really enforcing. This is what
# separates the two: one byte changed inside the signed shim, and the signature
# no longer validates. If the machine still boots, nothing was ever being
# checked and run 1 meant nothing.
mt mcopy ::/EFI/BOOT/BOOTX64.EFI /tmp/BOOTX64.EFI.orig >/dev/null 2>&1 \
    || fail "could not read BOOTX64.EFI off the ESP"
cp /tmp/BOOTX64.EFI.orig /tmp/BOOTX64.EFI.bad
# Well inside the PE image rather than in the header, so it is the signature
# that fails rather than the file being rejected as malformed.
printf '\xde\xad\xbe\xef' | dd of=/tmp/BOOTX64.EFI.bad bs=1 seek=100000 \
    conv=notrunc status=none
mt mcopy -o /tmp/BOOTX64.EFI.bad ::/EFI/BOOT/BOOTX64.EFI >/dev/null 2>&1 \
    || fail "could not write the damaged loader back"

boot tampered "$CODE_SB" "$VARS_MS" "$DENY_TIMEOUT" /output/sb-tampered.log
if grep -qa "SB-PROBE-START" /output/sb-tampered.log; then
    no "a damaged loader is refused" \
       "IT BOOTED — the firmware is not enforcing, so nothing above proved anything"
    tail -20 /output/sb-tampered.log | sed 's/^/      /'
else
    pass "a damaged loader is refused, so the firmware really is enforcing"
    grep -qaiE "security violation|access denied|verification failed" /output/sb-tampered.log \
        && pass "and the firmware says why" \
        || echo "  NOTE  the firmware refused it without an explanatory message"
fi

# Put it back.
mt mcopy -o /tmp/BOOTX64.EFI.orig ::/EFI/BOOT/BOOTX64.EFI >/dev/null 2>&1 \
    || fail "could not restore BOOTX64.EFI"

# --- 3. Secure Boot off: the image must still work ---------------------------
#
# The regression that would matter most in the field: most machines have Secure
# Boot disabled today, and an image that only boots with it on would break every
# one of them.
if [ -n "$CODE_PLAIN" ] && [ -n "$VARS_PLAIN" ]; then
    boot plain "$CODE_PLAIN" "$VARS_PLAIN" "$BOOT_TIMEOUT" /output/sb-off.log
    if grep -qa "SB-PROBE-START" /output/sb-off.log; then
        pass "the same image still boots with Secure Boot disabled"
    else
        no "the same image still boots with Secure Boot disabled" "(see /output/sb-off.log)"
        tail -30 /output/sb-off.log | sed 's/^/      /'
    fi
    # And it really was off, so this run is a different case from the first
    # rather than the same firmware twice under two names.
    state="$(sb_state /output/sb-off.log)"
    case "$state" in
        0|absent) pass "and that firmware really did have it off (probe: $state)";;
        "")       no "and that firmware really did have it off" "(the probe did not run)";;
        *)        no "and that firmware really did have it off" "(probe said '$state')";;
    esac
else
    echo "  SKIP  no plain OVMF firmware here to test the Secure-Boot-off case"
fi

echo ""
echo "$ok passed, $bad failed"
[ "$bad" -eq 0 ]
