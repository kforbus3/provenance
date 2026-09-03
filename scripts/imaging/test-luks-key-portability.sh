#!/bin/bash
# The LUKS bootstrap key must come from the machine, not from the image.
#
# This is the test that should have existed before encrypted updates shipped.
# Both bugs that made them impossible were in this one mechanism, both were
# found by imaging a real machine, and both were invisible until a second boot:
#
#   crypttab named `UUID=<luks uuid>` from the build's own luksFormat, so a
#   machine given a bundle from another build hunted for volumes that do not
#   exist on its disk -- "Waiting for encrypted source device", forever.
#
#   The keyfile was 4096 bytes of /dev/urandom drawn per build and baked into
#   the initramfs, so a bundle delivered the builder's key -- "No key available
#   with this passphrase", then an initramfs shell.
#
# Real loop device, real GPT, real LUKS, the real init-premount script. Runs in
# about a minute, which is why it belongs in the fast job: the boot tests take
# 50 and were not watching this at all.
#
#   docker run --rm --privileged -v "$PWD":/repo:ro ubuntu:24.04 \
#       bash /repo/scripts/test-luks-key-portability.sh
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IT="$REPO/builder/overlay/etc/initramfs-tools"
ok=0; fail=0
pass() { echo "  ok   $1"; ok=$((ok + 1)); }
bad()  { echo "  FAIL $1"; fail=$((fail + 1)); }

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq parted cryptsetup-bin util-linux e2fsprogs >/dev/null 2>&1

WORK=$(mktemp -d)
trap 'umount /mnt/ktb 2>/dev/null; cryptsetup close ktest 2>/dev/null; losetup -d "$LO" 2>/dev/null; rm -rf "$WORK"' EXIT

truncate -s 400M "$WORK/disk.img"
parted -s "$WORK/disk.img" mklabel gpt
parted -s "$WORK/disk.img" mkpart BOOT     ext4 1MiB 150MiB
parted -s "$WORK/disk.img" mkpart rootfs-a ext4 150MiB 100%
LO=$(losetup -f --show -P "$WORK/disk.img") || { echo "HARNESS-FAIL: losetup"; exit 1; }
BB=$(basename "$LO")
for n in 1 2; do
    [ -b "${LO}p$n" ] && continue
    IFS=: read -r mj mn < "/sys/class/block/${BB}p$n/dev"
    mknod "${LO}p$n" b "$mj" "$mn"
done

# --- make the BOOT label findable, and prove it before testing anything ------
#
# The script under test finds the partition with `blkid -t LABEL=BOOT`, and
# blkid answers from a cache. losetup -P scans the partitions the moment they
# appear -- before mkfs has written a label -- so the cache can hold a
# label-less entry for this very device, and blkid then reports no BOOT
# partition at all. The script does the right thing with that (warns, falls back
# to a passphrase prompt, exits 0) and the test records two failures that look
# like the product is broken when nothing about it changed.
#
# That is exactly the trap test-state-directives.sh documents for `blkid -L
# overlay`. Same fix here: drop the cache, then assert the lookup resolves to
# the device this test just made, so a future recurrence is reported as a
# harness fault instead of a product one.
blkid_cache_clear() { rm -f /run/blkid/blkid.tab /run/blkid/blkid.tab.old /etc/blkid.tab 2>/dev/null; }

resolve_boot() {                # resolve_boot -> device, or empty
    local i found
    for i in 1 2 3 4 5 6 7 8 9 10; do
        blkid_cache_clear
        found="$(blkid -l -t LABEL=BOOT -o device 2>/dev/null)"
        [ -n "$found" ] && { echo "$found"; return 0; }
        sleep 0.3
    done
    return 1
}

# The BOOT partition as build-image.sh writes it.
mkfs.ext4 -q -L BOOT "${LO}p1"
blkid_cache_clear
# --- make the label lookup deterministic ------------------------------------
#
# `blkid -t LABEL=BOOT` is a question about the whole machine, and a CI runner's
# root disk usually has its own partition labelled BOOT -- GitHub's answers
# /dev/nvme0n1p16. So the script under test would go looking at the runner's
# disk instead of this test's, which is what made this test fail intermittently
# on unrelated changes. It is not something ab-luks-key can do anything about:
# on a real machine being imaged, its own BOOT partition is the only one.
#
# A shim on PATH, applied unconditionally. Conditionally shimming would mean the
# test exercises a different path depending on what the host's disk happens to
# be called, which is how a flake survives being "fixed". The script still calls
# blkid with exactly the arguments it always did, and everything downstream --
# mounting, copying the key, the mode, the umount -- is the real thing against a
# real filesystem on a real loop device.
NATIVE="$(resolve_boot || true)"
if [ "$NATIVE" = "${LO}p1" ]; then
    echo "  note: blkid resolves LABEL=BOOT to this test's partition natively"
else
    echo "  note: this host has its own LABEL=BOOT (${NATIVE:-none}); the shim below"
    echo "        is what keeps this test about ab-luks-key rather than about the host"
fi
SHIM="$WORK/bin"; mkdir -p "$SHIM"
REAL_BLKID="$(command -v blkid)"
cat > "$SHIM/blkid" <<SHIMEOF
#!/bin/sh
# Answer the script's own lookup with this test's partition; delegate the rest.
for a in "\$@"; do
    case "\$a" in
        LABEL=BOOT|PARTLABEL=BOOT) echo "${LO}p1"; exit 0;;
    esac
done
exec "$REAL_BLKID" "\$@"
SHIMEOF
chmod +x "$SHIM/blkid"
PATH="$SHIM:$PATH"; export PATH
BOOTFOUND="$(blkid -l -t LABEL=BOOT -o device 2>/dev/null)"
[ "$BOOTFOUND" = "${LO}p1" ] || {
    echo "HARNESS-FAIL: the shimmed lookup returned '${BOOTFOUND:-nothing}'"
    exit 1
}

head -c 4096 /dev/urandom > "$WORK/machine.key"
mkdir -p /mnt/ktb && mount "${LO}p1" /mnt/ktb
install -d -m700 /mnt/ktb/ab-keys
install -m400 "$WORK/machine.key" /mnt/ktb/ab-keys/luks.key
umount /mnt/ktb

# A volume only the machine key opens. No passphrase slot on purpose: if the
# script can open this, the key it fetched is the only thing that could have.
cryptsetup luksFormat --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --key-file "$WORK/machine.key" "${LO}p2" >/dev/null 2>&1

mkdir -p /scripts /cryptroot
printf 'log_warning_msg() { echo "W: $*"; }\n' > /scripts/functions

echo "== the initramfs fetches this machine's key =="
rm -rf /cryptkey
printf 'luks-rootfs-a PARTLABEL=rootfs-a /cryptkey/luks.key luks,discard,initramfs\n' > /cryptroot/crypttab
blkid_cache_clear
sh "$IT/scripts/init-premount/ab-luks-key" >/dev/null 2>&1
if [ -f /cryptkey/luks.key ]; then
    pass "key placed at /cryptkey/luks.key"
    [ "$(stat -c %a /cryptkey/luks.key)" = "400" ] && pass "mode 400" || bad "mode is not 400"
    cmp -s /cryptkey/luks.key "$WORK/machine.key" && pass "bytes match the key on BOOT" \
        || bad "fetched key does not match the one on BOOT"
    if cryptsetup open --key-file /cryptkey/luks.key "${LO}p2" ktest 2>/dev/null; then
        pass "it unlocks a volume with no passphrase slot"
        cryptsetup close ktest
    else
        bad "the fetched key does not open the volume"
    fi
else
    bad "no key was placed; every encrypted machine would prompt at boot"
fi
mount | grep -q ab-bootpart && bad "left the BOOT partition mounted" || pass "BOOT unmounted again"

echo "== it does nothing once enrolment has moved crypttab to clevis =="
# This is what keeps luks-enroll-reap.sh honest: the reaper destroys the
# bootstrap keyslot only after a boot that did not use the bootstrap key.
rm -rf /cryptkey
printf 'luks-rootfs-a PARTLABEL=rootfs-a none luks,discard,initramfs\n' > /cryptroot/crypttab
blkid_cache_clear
sh "$IT/scripts/init-premount/ab-luks-key" >/dev/null 2>&1
[ -f /cryptkey/luks.key ] && bad "placed a key crypttab no longer asks for" \
    || pass "no key placed"

echo "== a missing key degrades to a prompt, not to an initramfs shell =="
rm -rf /cryptkey
mount "${LO}p1" /mnt/ktb && rm -f /mnt/ktb/ab-keys/luks.key && umount /mnt/ktb
printf 'luks-rootfs-a PARTLABEL=rootfs-a /cryptkey/luks.key luks,discard,initramfs\n' > /cryptroot/crypttab
blkid_cache_clear
out=$(sh "$IT/scripts/init-premount/ab-luks-key" 2>&1); rc=$?
[ "$rc" = 0 ] && pass "exits 0 so the boot continues to a passphrase prompt" \
    || bad "exit $rc would abort the boot"
case "$out" in *"no key at"*) pass "says why";; *) bad "silent about the missing key";; esac

echo "== the hook marks an initramfs that still uses the bootstrap key =="
# Without this marker every initramfs looks keyless, and the reaper would
# destroy the bootstrap keyslot on a boot the bootstrap key had just unlocked.
DESTDIR="$WORK/destdir"; export DESTDIR
mkdir -p "$DESTDIR" /usr/share/initramfs-tools
printf 'copy_exec() { :; }\n' > /usr/share/initramfs-tools/hook-functions
printf 'luks-rootfs-a PARTLABEL=rootfs-a /cryptkey/luks.key luks,discard,initramfs\n' > /etc/crypttab
sh "$IT/hooks/ab-luks-key" >/dev/null 2>&1
[ -f "$DESTDIR/cryptkey/bootstrap-key-in-use" ] && pass "marker written while the key is in use" \
    || bad "no marker — the reaper would call this initramfs keyless"

rm -rf "$DESTDIR"; mkdir -p "$DESTDIR"
printf 'luks-rootfs-a PARTLABEL=rootfs-a none luks,discard,initramfs\n' > /etc/crypttab
sh "$IT/hooks/ab-luks-key" >/dev/null 2>&1
[ -f "$DESTDIR/cryptkey/bootstrap-key-in-use" ] && bad "marker written for a clevis crypttab" \
    || pass "no marker once the key is out of crypttab"

echo ""
echo "$ok passed, failed: $fail"
[ "$fail" = 0 ] || exit 1
