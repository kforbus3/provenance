#!/bin/bash
# An image must carry nothing that belongs to the disk it was built on.
#
# This is the rule two shipped bugs broke, both found by imaging a machine
# rather than by CI, and both fatal in the same way: an update installs
# perfectly and the machine will not boot.
#
#   1. /etc/crypttab held `UUID=<luks uuid>` from `cryptsetup luksUUID`, which
#      is created by that luksFormat. A bundle carries the rootfs and the
#      initramfs built from it, so a machine given a bundle from another build
#      looked for three volumes that exist nowhere on its disk:
#        cryptsetup: Waiting for encrypted source device UUID=...
#
#   2. /etc/cryptsetup-keys.d/*.key held 4096 bytes of `/dev/urandom` drawn per
#      build, and cryptsetup-initramfs baked it into the initramfs. The bundle
#      then delivered the *builder's* key:
#        No key available with this passphrase.
#        ALERT!  LABEL=rootfs-b does not exist.  Dropping to a shell!
#
# Both are the same mistake, and neither needs a boot to detect -- which is the
# point of this script. It mounts a built image and asserts the rule directly,
# in seconds, so the next instance of it fails in CI instead of on a machine.
#
#   docker run --rm --privileged --platform=linux/amd64 \
#       -v "$PWD/output":/output -v "$PWD/scripts":/s \
#       --entrypoint bash debian-ab-builder:amd64 /s/test-image-portability.sh
set -u

IMAGE="${IMAGE:-/output/enc-target.img}"
LUKS_PASSPHRASE="${LUKS_PASSPHRASE:-testluks}"

ok=0; fail=0
pass() { echo "  ok   $1"; ok=$((ok + 1)); }
bad()  { echo "  FAIL $1"; fail=$((fail + 1)); }

[ -f "$IMAGE" ] || { echo "HARNESS-FAIL: no $IMAGE"; exit 1; }
echo "== $(basename "$IMAGE") =="

LO=$(losetup -f --show -P "$IMAGE") || { echo "HARNESS-FAIL: losetup"; exit 1; }
BB=$(basename "$LO")
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    [ -b "/dev/${BB}p$n" ] && continue
    IFS=: read -r mj mn < "/sys/class/block/${BB}p$n/dev"
    mknod "/dev/${BB}p$n" b "$mj" "$mn"
done

OPENED=""
cleanup() {
    umount /mnt/pslot 2>/dev/null || true
    umount /mnt/pboot 2>/dev/null || true
    for m in $OPENED; do cryptsetup close "$m" 2>/dev/null || true; done
    losetup -d "$LO" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p /mnt/pslot /mnt/pboot
ROOT=""
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    dev="/dev/${BB}p$n"
    if [ "$(blkid -o value -s TYPE "$dev" 2>/dev/null)" = "crypto_LUKS" ]; then
        map="port-p$n"
        printf '%s' "$LUKS_PASSPHRASE" | cryptsetup open "$dev" "$map" - 2>/dev/null || continue
        OPENED="$OPENED $map"
        dev="/dev/mapper/$map"
    fi
    mount -o ro "$dev" /mnt/pslot 2>/dev/null || continue
    if [ -d /mnt/pslot/etc/rauc ]; then ROOT="$dev"; break; fi
    umount /mnt/pslot
done
[ -n "$ROOT" ] || { echo "HARNESS-FAIL: no root slot in $IMAGE"; exit 1; }

CT=/mnt/pslot/etc/crypttab
if [ ! -f "$CT" ]; then
    echo "  (not an encrypted image; nothing to check)"
    exit 0
fi

echo "--- crypttab addresses volumes portably ---"
if grep -qE '^[^#].*[[:space:]]UUID=' "$CT"; then
    bad "crypttab names a LUKS UUID — that UUID exists only on the builder's disk"
    grep -E '^[^#].*UUID=' "$CT" | sed 's/^/       /'
else
    pass "no LUKS UUID in crypttab"
fi
for want in rootfs-a rootfs-b overlay; do
    if grep -qE "^luks-${want}[[:space:]]+PARTLABEL=${want}([[:space:]]|$)" "$CT"; then
        pass "luks-$want -> PARTLABEL=$want"
    else
        bad "luks-$want is not addressed by PARTLABEL"
    fi
done

echo "--- no LUKS key material in the root slot ---"
# The slot is what a bundle carries, and a bundle is published over plain HTTP.
if [ -n "$(ls -A /mnt/pslot/etc/cryptsetup-keys.d 2>/dev/null)" ]; then
    bad "/etc/cryptsetup-keys.d holds key material that an update would ship"
    ls -l /mnt/pslot/etc/cryptsetup-keys.d | sed 's/^/       /'
else
    pass "no keyfiles in the root slot"
fi
if grep -qE '^[^#]' "$CT" && ! grep -qE '[[:space:]]/cryptkey/luks\.key[[:space:]]' "$CT"; then
    if grep -qE '[[:space:]]none[[:space:]]' "$CT"; then
        pass "crypttab uses no keyfile (passphrase or clevis image)"
    else
        bad "crypttab keyfile column points somewhere other than /cryptkey/luks.key"
    fi
else
    pass "crypttab keyfile is the runtime path the initramfs fills in"
fi

echo "--- the key is on the BOOT partition, which no bundle writes ---"
if mount -o ro "/dev/${BB}p3" /mnt/pboot 2>/dev/null; then
    if grep -qE '[[:space:]]/cryptkey/luks\.key[[:space:]]' "$CT"; then
        if [ -f /mnt/pboot/ab-keys/luks.key ]; then
            perm=$(stat -c %a /mnt/pboot/ab-keys/luks.key)
            pass "BOOT carries ab-keys/luks.key (mode $perm)"
            [ "$perm" = "400" ] || bad "expected mode 400, got $perm"
        else
            bad "crypttab wants /cryptkey/luks.key but BOOT has no ab-keys/luks.key"
        fi
    fi
    for f in A/initrd.img B/initrd.img; do
        [ -f "/mnt/pboot/$f" ] && pass "slot initramfs present: $f"
    done
    # Left mounted on purpose; the initramfs check below reads from it and the
    # EXIT trap unmounts it.
else
    bad "could not mount the BOOT partition"
fi

echo "--- the initramfs fetches the key rather than carrying one ---"
if [ -f /mnt/pslot/etc/initramfs-tools/scripts/init-premount/ab-luks-key ]; then
    pass "init-premount/ab-luks-key is in the image"
    [ -x /mnt/pslot/etc/initramfs-tools/scripts/init-premount/ab-luks-key ] \
        && pass "and is executable (initramfs-tools ignores it otherwise)" \
        || bad "init-premount/ab-luks-key is not executable"
else
    bad "init-premount/ab-luks-key is missing; nothing would supply the key"
fi
# Anchored, because Debian's shipped conf-hook documents the setting in four
# comment lines including a commented-out `#KEYFILE_PATTERN=`. An unanchored
# grep calls a correct image broken, which is a worse test than none: it trains
# whoever sees it to disbelieve the suite.
if grep -qE '^[[:space:]]*KEYFILE_PATTERN=' /mnt/pslot/etc/cryptsetup-initramfs/conf-hook 2>/dev/null; then
    bad "KEYFILE_PATTERN is set — the initramfs would bake in a build-time key"
    grep -nE '^[[:space:]]*KEYFILE_PATTERN=' /mnt/pslot/etc/cryptsetup-initramfs/conf-hook | sed 's/^/       /'
else
    pass "no active KEYFILE_PATTERN"
fi

echo "--- and the generated initramfs proves it ---"
# The end of the chain: whatever the config says, this is what the machine boots.
if command -v lsinitramfs >/dev/null 2>&1 && [ -f /mnt/pboot/A/initrd.img ]; then
    L="$(lsinitramfs /mnt/pboot/A/initrd.img 2>/dev/null)"
    printf '%s\n' "$L" | grep -q 'init-premount/ab-luks-key' \
        && pass "slot A initramfs contains the key-fetch script" \
        || bad "slot A initramfs has no key-fetch script; it would prompt at boot"
    printf '%s\n' "$L" | grep -q 'cryptkey/bootstrap-key-in-use' \
        && pass "and the marker luks-enroll-reap depends on" \
        || bad "no bootstrap marker; the reaper would call this initramfs keyless"
    printf '%s\n' "$L" | grep -q 'cryptsetup-keys\.d' \
        && bad "the initramfs still carries a build-time keyfile" \
        || pass "and no key material of its own"
else
    echo "  (lsinitramfs unavailable or no slot kernel; skipping)"
fi

echo ""
echo "$ok passed, $fail failed"
[ "$fail" = 0 ] || exit 1
