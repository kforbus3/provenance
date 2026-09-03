#!/bin/bash
# Install a RAUC update bundle on a booted machine, and prove the slot flipped.
#
# Building a bundle proves nothing on its own: it has to be signed by a key the
# image trusts, carry a matching `compatible`, and land in the slot the machine
# is not running on. All three fail independently and only the running machine
# can tell you.
#
# Boot 1: running slot A, install the bundle, report what rauc thinks.
# Boot 2: the machine should now be on slot B, with slot A still intact.
#
# The bundle is served to the guest over QEMU's user networking (the host is
# 10.0.2.2 from inside), so nothing outside this container is involved.
#
#   docker run --rm --privileged --platform=linux/amd64 \
#       -v "$PWD/output":/output -v "$PWD/scripts":/s \
#       --entrypoint bash debian-ab-builder:amd64 /s/test-update-bundle.sh
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq qemu-system-x86 gdisk util-linux nginx-light curl >/dev/null 2>&1

SRC="${SRC:-/output/upd-test.img}"
DISK="${DISK:-/output/update-target.img}"
BUNDLE="${BUNDLE:-}"
SIZE="${SIZE:-32G}"
PORT=8000
# Namespaces the boot logs so an encrypted run and a plain one can both be
# looked at afterwards instead of the second overwriting the first.
TAG="${TAG:+$TAG-}"

fail() { echo "HARNESS-FAIL: $*"; exit 1; }
[ -f "$SRC" ] || fail "no $SRC"

if [ -z "$BUNDLE" ]; then
    BUNDLE="$(ls -t /output/bundles/*.raucb 2>/dev/null | head -1)"
fi
[ -n "$BUNDLE" ] && [ -f "$BUNDLE" ] || fail "no bundle in /output/bundles"
echo "  bundle: $(basename "$BUNDLE")"

rm -f "$DISK"
truncate -s "$SIZE" "$DISK"
dd if="$SRC" of="$DISK" bs=4M conv=notrunc status=none || fail "dd"

# --- the imager's post-write steps -------------------------------------------
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

# --- install a probe into slot A ---------------------------------------------
#
# On an encrypted image the root slot is a LUKS container, so mounting the
# partition cannot work and the search below found nothing ("no root slot
# found") before a single boot had happened. Open any crypto_LUKS partition
# first and search the mapper instead. LUKS_PASSPHRASE is what the image was
# built with; without it, encrypted images are simply skipped rather than
# reported as a broken harness.
OPENED=""
cleanup_luks() {
    for m in $OPENED; do
        umount "/dev/mapper/$m" 2>/dev/null || true
        cryptsetup close "$m" 2>/dev/null || true
    done
    OPENED=""
}
trap 'cleanup_luks; rm -f "$DISK"' EXIT

# Deliberately not a function returning a list: command substitution runs in a
# subshell, so every mapper it opened would be invisible to cleanup_luks and
# stay open after the script exits, holding the loop device that QEMU is about
# to boot from.
ROOTDEV=""
mkdir -p /mnt/slot /mnt/boot
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    dev="/dev/${BB}p$n"
    if [ "$(blkid -o value -s TYPE "$dev" 2>/dev/null)" = "crypto_LUKS" ]; then
        [ -n "${LUKS_PASSPHRASE:-}" ] || continue
        map="abtest-p$n"
        printf '%s' "$LUKS_PASSPHRASE" | cryptsetup open "$dev" "$map" - 2>/dev/null || continue
        OPENED="$OPENED $map"
        dev="/dev/mapper/$map"
    fi
    mount "$dev" /mnt/slot 2>/dev/null || continue
    if [ -d /mnt/slot/etc/rauc ] && [ -d /mnt/slot/usr/local/sbin ]; then ROOTDEV="$dev"; break; fi
    umount /mnt/slot
done
[ -n "$ROOTDEV" ] || fail "no root slot found (encrypted image without LUKS_PASSPHRASE?)"
echo "  root slot: $ROOTDEV"

cat > /mnt/slot/usr/local/sbin/ab-update-probe.sh <<PROBE
#!/bin/sh
exec > /dev/console 2>&1
echo "AB-UPDATE-PROBE-START"
echo "booted-slot:  \$(sed -n 's/.*rauc.slot=\([AB]\).*/\1/p' /proc/cmdline)"
echo "keyring:      \$(openssl x509 -in /etc/rauc/keyring.pem -noout -subject 2>/dev/null || echo 'not a single certificate')"
if [ -f /var/lib/ab-update-done ]; then
    echo "phase:        second boot (after update)"
    echo "--- rauc status ---"
    rauc status 2>&1 | head -20
else
    echo "phase:        first boot (installing)"
    touch /var/lib/ab-update-done
    echo "--- rauc status before ---"
    rauc status 2>&1 | head -12
    echo "--- installing ---"
    # Keep the whole log, not the tail: which route the install took (streamed,
    # or downloaded after streaming failed) is the thing worth knowing when this
    # breaks, and the tail cuts exactly that off.
    ab-update "http://10.0.2.2:${PORT}/bundles/$(basename "$BUNDLE")" 2>&1 | tee /tmp/upd.log | tail -40
    if grep -q "Streaming the update failed" /tmp/upd.log; then
        echo "install-route:  downloaded (streaming failed and the fallback took over)"
    else
        echo "install-route:  streamed"
    fi
    echo "--- rauc status after ---"
    rauc status 2>&1 | head -20
fi
echo "AB-UPDATE-PROBE-END"
systemctl poweroff --no-block
PROBE
chmod 0755 /mnt/slot/usr/local/sbin/ab-update-probe.sh

cat > /mnt/slot/etc/systemd/system/ab-update-probe.service <<'UNIT'
[Unit]
Description=Install an update bundle and report, then power off
After=multi-user.target network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ab-update-probe.sh
TimeoutStartSec=600
[Install]
WantedBy=multi-user.target
UNIT
mkdir -p /mnt/slot/etc/systemd/system/multi-user.target.wants
ln -sf /etc/systemd/system/ab-update-probe.service \
   /mnt/slot/etc/systemd/system/multi-user.target.wants/ab-update-probe.service

# The guest gets its address from QEMU's built-in DHCP; the image uses
# systemd-networkd, which needs to be told to accept it on the virtio NIC.
mkdir -p /mnt/slot/etc/systemd/network
cat > /mnt/slot/etc/systemd/network/20-dhcp.network <<'NET'
[Match]
Name=en*
[Network]
DHCP=yes
NET
sync; umount /mnt/slot

mount "/dev/${BB}p3" /mnt/boot 2>/dev/null && {
    sed -i 's/ quiet//g; s/^set timeout=.*/set timeout=1/' /mnt/boot/grub/grub.cfg
    # Deliberately destroy slot B's kernel before the update. Both kernels are
    # byte-identical here, so comparing them after the fact would prove nothing;
    # a slot B that boots afterwards can only mean the update actually replaced
    # it. Slot A -- the one running -- is left alone, which is also the point:
    # an update must not touch the kernel the machine is currently relying on.
    if [ -f /mnt/boot/B/vmlinuz ]; then
        echo "  slot layout: $(ls /mnt/boot/A /mnt/boot/B | tr '\n' ' ')"
        printf 'NOT A KERNEL' > /mnt/boot/B/vmlinuz
        printf 'NOT AN INITRAMFS' > /mnt/boot/B/initrd.img
        echo "  slot B kernel deliberately corrupted before the update"
    else
        echo "  NOTE: this image has no per-slot kernels; skipping the kernel check"
    fi
    umount /mnt/boot
}
# Every mapper has to be closed before the loop device goes, or losetup -d
# leaves the disk held open and QEMU boots a file the kernel is still writing.
cleanup_luks
losetup -d "$LO"

# --- serve the bundle to the guest -------------------------------------------
#
# nginx, not busybox httpd, because this is the only thing that decides whether
# `rauc install <url>` works and busybox is not the server production uses.
#
# RAUC streams a bundle as an NBD device backed by HTTP range requests, and its
# backend requires 206 on every read with exactly the requested byte count --
# anything else is NBD_EIO, the device is torn down, and dm-verity is then set
# up against a device with no size ("Hash device is too small (-E2BIG)"), which
# is what this test reported for a week. busybox httpd answers a range that is
# wholly past EOF with 200 and the entire file, where nginx answers 416; the
# 200 fails RAUC's response-code check and the oversized body overruns its read
# buffer. Testing streaming against a server that behaves nothing like the one
# in server/http told us nothing about whether streaming works.
cat > /etc/nginx/nginx.conf <<EOF
daemon off;
# Workers as root: /output is a mounted volume whose ownership is the host's,
# and a 403 here would read as a streaming failure.
user root;
error_log /dev/stderr warn;
events { worker_connections 64; }
http {
    access_log off;
    include /etc/nginx/mime.types;
    server {
        listen ${PORT};
        root /output;
        autoindex on;
        sendfile on;
    }
}
EOF
nginx &
HTTPD=$!
# Replaces the cleanup_luks trap, so it has to keep doing that job too --
# otherwise a failure between here and the end leaves mappers open.
trap 'kill $HTTPD 2>/dev/null; cleanup_luks; rm -f "$DISK"' EXIT
sleep 1
# Fail here rather than 900 seconds into a boot that could never have worked.
curl -fsS -o /dev/null -r 0-3 "http://127.0.0.1:${PORT}/bundles/$(basename "$BUNDLE")" \
    || fail "the bundle is not being served over HTTP"

boot() {
    echo ""
    echo "=== boot: $1 ==="
    timeout 900 qemu-system-x86_64 -m 2048 -smp 2 \
        -drive file="$DISK",format=raw,if=virtio \
        -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
        -nographic -serial mon:stdio -no-reboot > "/output/update-${TAG}$1.log" 2>&1
    sed -n '/AB-UPDATE-PROBE-START/,/AB-UPDATE-PROBE-END/p' "/output/update-${TAG}$1.log" \
        | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' | sed 's/^/  /'
}

boot install
boot after-reboot

# The probe lives in slot A. After a successful update the machine boots slot B,
# whose contents came from the bundle -- so the probe is NOT there, and its
# absence is the point rather than a failure. What proves the update is that
# slot B boots at all and identifies itself as the bundle's image.
echo ""
echo "=== result ==="
AFTER="/output/update-${TAG}after-reboot.log"
ok=1
grep -qa "Slot B (rootfs.1)" "$AFTER" || { echo "  FAIL: GRUB did not select slot B"; ok=0; }
# The encrypted regression, named explicitly because its symptom is silence.
# crypttab used to carry the LUKS UUIDs of the build that produced the image, so
# a bundle from a *different* build gave the machine three volumes that exist
# nowhere on its disk: slot B waited on all of them forever and the monitor
# showed a cursor. Addressing them by PARTLABEL is what fixes it, and this is
# what proves the fix rather than assuming it.
grep -qa "Waiting for encrypted source device" "$AFTER" && {
    echo "  FAIL: slot B is waiting for encrypted devices that are not on this disk"
    echo "        (crypttab carrying build-time identity — see build-image.sh)"
    grep -a "Waiting for encrypted source device" "$AFTER" | tail -3 | sed 's/^/        /'
    ok=0; }
# Specifically the root device, not any "does not exist" line: the boot log
# routinely contains others (systemd noting /sbin/tomoyo-init is absent), and
# matching those reported a failure on a machine that had booted perfectly.
grep -qa "LABEL=rootfs-b does not exist" "$AFTER" && {
    echo "  FAIL: slot B has no filesystem label — the post-install hook did not run"; ok=0; }
grep -qa "Welcome to" "$AFTER" || { echo "  FAIL: slot B did not reach userspace"; ok=0; }
# The kernel check reads the disk rather than the hook's output: RAUC does not
# surface hook stdout in the install log, so grepping for it reported a missing
# kernel on a machine that had just booted the new one.
LO=$(losetup -f --show -P "$DISK"); BB=$(basename "$LO")
IFS=: read -r mj mn < "/sys/class/block/${BB}p3/dev"
rm -f "/dev/${BB}p3"; mknod "/dev/${BB}p3" b "$mj" "$mn"
mkdir -p /mnt/bootchk && mount "/dev/${BB}p3" /mnt/bootchk
ksize=$(stat -c %s /mnt/bootchk/B/vmlinuz 2>/dev/null || echo 0)
# The version stamp the same hook writes, read from the disk for the same reason
# as the kernel. This is what the fleet agent reports, and it is the entire
# basis on which a rollout decides whether a machine took the update: without
# it every machine keeps reporting the version it was imaged with, every rollout
# runs forever, and nothing anywhere says why.
bver=$(cat /mnt/bootchk/B/ab-version 2>/dev/null || echo "")
umount /mnt/bootchk; losetup -d "$LO"
if [ "$ksize" -gt 1000000 ]; then
    echo "  slot B kernel restored by the update: $ksize bytes"
else
    echo "  FAIL: slot B's kernel was not replaced (size $ksize)"; ok=0
fi
if [ -n "$bver" ]; then
    echo "  slot B stamped with bundle version: $bver"
else
    echo "  FAIL: slot B has no /boot/B/ab-version — the agent cannot tell the"
    echo "        control plane which version this machine took, so any rollout"
    echo "        containing it would never finish"
    ok=0
fi
grep -qa "ab-mark-good" "$AFTER" || echo "  WARN: ab-mark-good did not run in slot B"
if [ "$ok" = 1 ]; then
    echo "  PASS: installed on slot A, rebooted into slot B, and slot B came up"
    echo "  slot B identifies as: $(grep -a "login:" "$AFTER" | tail -1 | sed "s/ login:.*//;s/^ *//")"
else
    echo "  see $AFTER"
    exit 1
fi
