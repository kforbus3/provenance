#!/bin/bash
# A bundle from one build must be installable on a machine imaged from another.
#
# This is the scenario that broke twice, and the only one that ever exercises it:
# two *independent* builds. One build produces the machine, a different build
# produces the bundle, and every piece of build-time identity that leaked into an
# image showed up here and nowhere else.
#
#   crypttab held that build's LUKS UUIDs -> "Waiting for encrypted source
#   device", on all three volumes, forever.
#
#   the initramfs held that build's keyfile -> "No key available with this
#   passphrase", then an initramfs shell.
#
# The nightly catches these by booting, which costs fifty minutes and an x86
# runner. This asserts the same property without booting anything: it takes the
# initramfs *out of the bundle*, runs it against the *other* image's disk, and
# checks it unlocks. Architecture-independent, a couple of minutes, and it fails
# with the reason rather than with a timeout.
#
#   MACHINE=/output/enc-local.img BUNDLE=/output/bundles/x.raucb \
#   docker run --rm --privileged -v "$PWD/output":/output -v "$PWD/scripts":/s \
#       --entrypoint bash debian-ab-builder:arm64 /s/test-cross-build-update.sh
set -u

MACHINE="${MACHINE:-/output/enc-local.img}"
BUNDLE="${BUNDLE:-}"
LUKS_PASSPHRASE="${LUKS_PASSPHRASE:-testluks}"

ok=0; fail=0
pass() { echo "  ok   $1"; ok=$((ok + 1)); }
bad()  { echo "  FAIL $1"; fail=$((fail + 1)); }

[ -f "$MACHINE" ] || { echo "HARNESS-FAIL: no machine image at $MACHINE"; exit 1; }
if [ -z "$BUNDLE" ]; then
    BUNDLE="$(ls -t /output/bundles/*.raucb 2>/dev/null | head -1)"
fi
[ -f "$BUNDLE" ] || { echo "HARNESS-FAIL: no bundle"; exit 1; }

echo "== machine: $(basename "$MACHINE")   bundle: $(basename "$BUNDLE") =="

WORK=$(mktemp -d)
LO=""
cleanup() {
    umount /mnt/xboot 2>/dev/null || true
    umount "$WORK/bmnt" 2>/dev/null || true
    cryptsetup close xtest 2>/dev/null || true
    [ -n "$LO" ] && losetup -d "$LO" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

# --- what the bundle carries -------------------------------------------------
# A .raucb is a squashfs. Read it rather than trusting make-bundle.sh.
mkdir -p "$WORK/bmnt"
mount -t squashfs -o ro,loop "$BUNDLE" "$WORK/bmnt" 2>/dev/null \
    || { echo "HARNESS-FAIL: cannot mount the bundle"; exit 1; }

mkdir -p "$WORK/root"
tar -C "$WORK/root" -xzf "$WORK/bmnt/rootfs.tar.gz" \
    ./etc/crypttab ./etc/initramfs-tools 2>/dev/null || true

echo "--- the bundle carries no key material ---"
if tar -tzf "$WORK/bmnt/rootfs.tar.gz" 2>/dev/null | grep -q 'cryptsetup-keys\.d/.*\.key'; then
    bad "the bundle contains LUKS keyfiles — and bundles are published over HTTP"
else
    pass "no keyfiles in the bundle's rootfs"
fi

echo "--- the bundle's crypttab is about no particular disk ---"
CT="$WORK/root/etc/crypttab"
if [ -f "$CT" ]; then
    if grep -qE '^[^#].*[[:space:]]UUID=' "$CT"; then
        bad "the bundle's crypttab names LUKS UUIDs from the build that made it"
        grep -E '^[^#].*UUID=' "$CT" | sed 's/^/       /'
    else
        pass "no build-specific UUIDs"
    fi
    grep -qE '^luks-rootfs-b[[:space:]]+PARTLABEL=rootfs-b' "$CT" \
        && pass "addressed by PARTLABEL" || bad "not addressed by PARTLABEL"
else
    bad "the bundle has no /etc/crypttab"
fi

# --- the machine, from a different build ------------------------------------
LO=$(losetup -f --show -P "$MACHINE") || { echo "HARNESS-FAIL: losetup"; exit 1; }
BB=$(basename "$LO")
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    [ -b "/dev/${BB}p$n" ] && continue
    IFS=: read -r mj mn < "/sys/class/block/${BB}p$n/dev"
    mknod "/dev/${BB}p$n" b "$mj" "$mn"
done

echo "--- the two builds really are independent ---"
# If they share a key the test below proves nothing, so check first.
mkdir -p /mnt/xboot
mount -o ro "/dev/${BB}p3" /mnt/xboot 2>/dev/null \
    || { echo "HARNESS-FAIL: cannot mount the machine's BOOT partition"; exit 1; }
if [ -f /mnt/xboot/ab-keys/luks.key ]; then
    pass "the machine has its own key on BOOT"
else
    bad "the machine has no key on BOOT; nothing could unlock it unattended"
fi
# Without this the whole test can pass vacuously: if both builds happened to
# share a key, the unlock at the end would prove nothing about where the key
# came from. SOURCE is the image the bundle was built from; give it and the
# independence is asserted rather than assumed.
if [ -n "${SOURCE:-}" ] && [ -f "$SOURCE" ]; then
    SLO=$(losetup -f --show -P "$SOURCE")
    SBB=$(basename "$SLO")
    IFS=: read -r smj smn < "/sys/class/block/${SBB}p3/dev"
    rm -f "${SLO}p3"; mknod "${SLO}p3" b "$smj" "$smn"
    mkdir -p "$WORK/sboot"
    if mount -o ro "${SLO}p3" "$WORK/sboot" 2>/dev/null; then
        a=$(sha256sum /mnt/xboot/ab-keys/luks.key | cut -d' ' -f1)
        b=$(sha256sum "$WORK/sboot/ab-keys/luks.key" 2>/dev/null | cut -d' ' -f1)
        if [ -n "$b" ] && [ "$a" != "$b" ]; then
            pass "the two builds have different keys (${a:0:8}… vs ${b:0:8}…)"
        else
            bad "both builds carry the same key — the unlock below would prove nothing"
        fi
        umount "$WORK/sboot"
    fi
    losetup -d "$SLO" 2>/dev/null || true
else
    echo "  note: pass SOURCE=<the image the bundle came from> to assert the two"
    echo "        builds do not share a key"
fi
if tar -xzf "$WORK/bmnt/boot.tar.gz" -O ./A/initrd.img > "$WORK/bundle-initrd" 2>/dev/null \
   || tar -xzf "$WORK/bmnt/boot.tar.gz" -O ./initrd.img > "$WORK/bundle-initrd" 2>/dev/null; then
    pass "extracted the initramfs the bundle would install"
else
    echo "HARNESS-FAIL: the bundle carries no initramfs"; exit 1
fi
if lsinitramfs "$WORK/bundle-initrd" 2>/dev/null | grep -q 'cryptsetup-keys\.d'; then
    bad "the bundle's initramfs carries a keyfile from the build that made it"
else
    pass "the bundle's initramfs carries no key of its own"
fi

# --- the actual question -----------------------------------------------------
echo "--- the bundle's initramfs unlocks THIS machine ---"
mkdir -p "$WORK/initrd"
if ! unmkinitramfs "$WORK/bundle-initrd" "$WORK/initrd" 2>/dev/null; then
    echo "HARNESS-FAIL: cannot unpack the bundle's initramfs"; exit 1
fi
SCRIPT="$(find "$WORK/initrd" -path '*/init-premount/ab-luks-key' | head -1)"
if [ -z "$SCRIPT" ]; then
    bad "the bundle's initramfs has no key-fetch script; this machine would prompt"
else
    pass "the bundle's initramfs carries the key-fetch script"
    # Run it exactly as the initramfs would, with the machine's disk attached.
    umount /mnt/xboot
    mkdir -p /scripts /cryptroot
    printf 'log_warning_msg() { echo "W: $*"; }\n' > /scripts/functions
    cp "$WORK/root/etc/crypttab" /cryptroot/crypttab 2>/dev/null
    rm -rf /cryptkey
    sh "$SCRIPT" >/dev/null 2>&1
    if [ -f /cryptkey/luks.key ]; then
        pass "it fetched a key from this machine's BOOT partition"
        # The whole point: a volume created by the *other* build's luksFormat,
        # opened with the key this machine carries.
        if cryptsetup open --key-file /cryptkey/luks.key "/dev/${BB}p5" xtest 2>/dev/null; then
            pass "and it UNLOCKS this machine's slot B — cross-build update works"
            cryptsetup close xtest
        else
            bad "the fetched key does not open this machine's slot B"
        fi
    else
        bad "it fetched no key; this machine would drop to a passphrase prompt"
    fi
fi

echo ""
echo "$ok passed, failed: $fail"
[ "$fail" = 0 ] || exit 1
