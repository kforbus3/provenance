#!/bin/bash
#
# Build the netboot imager: a kernel + initramfs that auto-images a machine's
# local disk from an HTTP image URL.
#
# amd64 goes to /output/imager/{vmlinuz,initramfs.img} and every other
# architecture to /output/imager/<arch>/. amd64 keeps the top-level path it has
# always had so that servers and images already deployed keep working; nothing
# has to be rebuilt or moved to gain arm64 support. boot.ipxe picks the right
# directory from iPXE's own ${buildarch}, so the machine chooses, not the config.
#
# Runs inside the imager builder container (see Dockerfile).
set -euo pipefail

ARCH="${ARCH:-amd64}"
case "$ARCH" in
    amd64) OUT="${OUT:-/output/imager}";;
    arm64) OUT="${OUT:-/output/imager/arm64}";;
    *) echo "[imager-build] unsupported ARCH '$ARCH' (expected amd64 or arm64)" >&2; exit 2;;
esac
HERE="$(cd "$(dirname "$0")" && pwd)"

log() { echo -e "\033[0;32m[imager-build]\033[0m $*"; }
# Failures here ship a broken imager to every machine that netboots, so they end
# the build loudly rather than being carried past by a warning nobody reads.
die() { echo -e "\033[0;31m[imager-build] ERROR:\033[0m $*" >&2; exit 1; }

mkdir -p "$OUT"
WORK="$(mktemp -d)"
ROOT="$WORK/initrd"
mkdir -p "$ROOT"/{bin,sbin,etc,proc,sys,dev,tmp,newroot,usr/bin,usr/sbin,usr/share/udhcpc,lib,lib64}

KVER="$(ls /lib/modules | sort -V | tail -n1)"
log "Kernel version: $KVER"

# --- Kernel ---
# Staged, and NOT published until the initramfs beside it has been built and
# verified. Two reasons, and the second is the one that bites:
#
#   A plain `cp` onto the served path truncates it first and fills it after, so a
#   machine netbooting mid-build fetches a partial kernel.
#
#   The kernel and the initramfs are a PAIR -- the initramfs carries modules built
#   for exactly this kernel version. Publishing the kernel early means a build
#   that fails afterwards leaves a new vmlinuz beside the previous initramfs, and
#   the moment a kernel bump is involved that machine boots a kernel whose modules
#   it does not have: no network driver, no storage driver, and nothing that says
#   why. So both are staged and published together at the end.
TMP_KERNEL="$OUT/.vmlinuz.$$"
cp "/boot/vmlinuz-${KVER}" "$TMP_KERNEL"

# --- Busybox (provides sh, wget, gzip, ip, udhcpc, dd, mknod, etc.) ---
cp /bin/busybox "$ROOT/bin/busybox"
ln -sf busybox "$ROOT/bin/sh"

# --- Real zstd binary (busybox has no zstd) plus its shared libraries ---
copy_with_libs() {
    local bin="$1" dst="$2"
    cp "$bin" "$ROOT/$dst/"
    ldd "$bin" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*' | while read -r lib; do
        local d="$ROOT$(dirname "$lib")"
        mkdir -p "$d"; cp -L "$lib" "$d/" 2>/dev/null || true
    done
}
copy_with_libs "$(command -v zstd)" usr/bin
# sgdisk relocates the GPT backup header after the image lands on a disk that is
# bigger than the image (see init). busybox has nothing that can do this.
copy_with_libs "$(command -v sgdisk)" usr/sbin
# The dynamic loader itself.
for ldso in /lib64/ld-linux-x86-64.so.2 /lib/ld-linux-aarch64.so.1 /lib/ld-linux.so.2; do
    [ -f "$ldso" ] && { mkdir -p "$ROOT$(dirname "$ldso")"; cp -L "$ldso" "$ROOT$ldso"; }
done

# --- Module loader (kmod), so modules can stay compressed ---
#
# Debian ships modules as .ko.xz. busybox's modprobe cannot decompress them, so
# this used to expand the whole tree in place -- which is what made the initramfs
# 527 MB unpacked, 504 MB of it modules, for a machine to hold in RAM at boot.
# Shipping the real modprobe instead keeps them compressed: ~4x less memory for
# the same download, since gzip was not compressing already-compressed modules
# anyway.
#
# modprobe and depmod are both symlinks to one multicall binary that dispatches
# on argv[0], so the binary is copied once and the names are recreated as links.
KMOD_BIN="$(readlink -f "$(command -v modprobe)")"
copy_with_libs "$KMOD_BIN" usr/bin
# Absolute targets: these are resolved inside the initramfs at boot, where
# /usr/bin/kmod is exactly where the binary lands.
ln -sf /usr/bin/kmod "$ROOT/sbin/modprobe"
ln -sf /usr/bin/kmod "$ROOT/sbin/depmod"
# modinfo costs nothing (same binary, one more symlink) and is how the check
# below reads a compressed module -- and how anyone debugging a machine that
# will not see its NIC can ask what a module is.
ln -sf /usr/bin/kmod "$ROOT/sbin/modinfo"

# kmod DLOPENS its decompressors -- they are not in the ELF's NEEDED list, so
# ldd does not report them and copy_with_libs cannot see them. Without these,
# modprobe runs, finds the module, and fails to decompress it: no network driver,
# no storage driver, and an imager that boots and then cannot reach anything.
for soname in liblzma.so.5 libzstd.so.1; do
    lib="$(ldconfig -p | awk -v s="$soname" '$1 == s { print $NF; exit }')"
    [ -n "$lib" ] || die "kmod needs $soname to decompress modules, and it is not on this system"
    mkdir -p "$ROOT$(dirname "$lib")"
    cp -L "$lib" "$ROOT$(dirname "$lib")/"
done

# --- Kernel modules ---
# The entire tree, so dependency resolution always succeeds across arbitrary
# hardware (NICs, storage controllers) -- left compressed exactly as shipped.
MODSRC="/lib/modules/$KVER"
mkdir -p "$ROOT/lib/modules/$KVER"
cp -a "$MODSRC"/. "$ROOT/lib/modules/$KVER/"
# The real depmod, and it must succeed: modprobe resolves dependencies purely
# from modules.dep, so a tree without one loads nothing. This was `|| true`, which
# is survivable only when the initramfs regenerates it at boot -- and busybox's
# depmod cannot read compressed modules, so that fallback is gone on purpose.
depmod -b "$ROOT" "$KVER" || die "depmod failed; modprobe would resolve nothing at boot"

# Prove the chain against the tree about to be packed, using the SHIPPED binary
# and the SHIPPED libraries -- chrooted, so nothing on the build host stands in
# for something the initramfs is missing. Checking with the host's modprobe would
# pass with liblzma absent, which is precisely the failure worth catching.
#
# Two different things are being proven and both matter:
#   --show-depends reads modules.dep and resolves dependencies, but never opens a
#     module, so it says nothing about decompression.
#   modinfo on a .ko.xz has to decompress it, which is the dlopened-liblzma path.
# Loading itself needs a running kernel and is the one step left to the machine.
for probe in ext4 virtio_net e1000; do
    chroot "$ROOT" /sbin/modprobe -S "$KVER" --show-depends "$probe" >/dev/null 2>&1 \
        || die "the shipped modprobe cannot resolve '$probe' from the packed module tree"
done
SAMPLE="$(find "$ROOT/lib/modules/$KVER" -name 'ext4.ko*' | head -n1)"
[ -n "$SAMPLE" ] || die "no ext4 module in the tree to verify decompression against"
chroot "$ROOT" /sbin/modinfo -F description "${SAMPLE#$ROOT}" >/dev/null 2>&1 \
    || die "the shipped modinfo cannot decompress ${SAMPLE##*/} -- a dlopened decompressor (liblzma/libzstd) is missing from the initramfs"
log "Module tree: compressed, depmod clean, shipped modprobe resolves and decompresses"

# --- udhcpc callback + init ---
cp "$HERE/udhcpc.script" "$ROOT/usr/share/udhcpc/default.script"
chmod +x "$ROOT/usr/share/udhcpc/default.script"
cp "$HERE/init" "$ROOT/init"
chmod +x "$ROOT/init"

# --- Pack the initramfs ---
#
# Packed beside the destination and moved into place, never written to it
# directly. A redirect onto $OUT/initramfs.img truncates it the moment packing
# starts and then fills it over the several minutes the module tree takes, and
# that file is the one the PXE server is serving RIGHT NOW. Any machine that
# netboots during a rebuild gets a complete kernel and a half-written initramfs,
# unpacks an archive with no /init in it, and panics with "No working init
# found" -- with nothing in the build output to say why, because by the time
# anyone looks the file is whole again.
#
# A rename within one filesystem is atomic, so a machine gets either the
# previous imager or the new one. The same property covers a build that dies
# partway: the working artifact it would otherwise have destroyed is untouched,
# because nothing replaces it until there is something complete to replace it
# with.
log "Packing initramfs"
TMP_IMG="$OUT/.initramfs.img.$$"
trap 'rm -f "$TMP_IMG" "$TMP_KERNEL"' EXIT
# cpio's stderr is kept. It was discarded, which is what made a bad pack silent
# -- and a silent bad pack is exactly what ships a broken imager.
( cd "$ROOT" && find . | cpio -o -H newc | gzip -9 ) > "$TMP_IMG"

# Verify what was actually produced, not what was intended. Shared with
# verify-initramfs.sh so the check the build runs is the same one an operator can
# run against a server's live artifact when a machine panics on netboot.
log "Verifying the packed initramfs"
"$HERE/verify-initramfs.sh" "$TMP_IMG" \
    || die "the packed initramfs is not bootable; the existing imager has been left in place"

# The publish. Everything above happened beside the live artifacts; this is the
# only moment they change. Two renames back to back rather than one atomic step,
# because they are two files -- but the window in which a machine could see a
# mismatched pair is now the microseconds between these lines, rather than the
# minutes the build takes.
mv -f "$TMP_IMG" "$OUT/initramfs.img"
mv -f "$TMP_KERNEL" "$OUT/vmlinuz"
trap - EXIT

echo "$KVER" > "$OUT/KERNEL_VERSION"

# --- what this imager understands ---------------------------------------------
#
# The imager is a build artifact: `init` is baked into the initramfs, so a repo
# that has grown a new imager.* parameter does nothing until someone runs
# `make imager`. Nothing said so, and the failure is silent in the worst way --
# the iPXE script passes imager.hostname=, an older imager ignores unknown
# parameters exactly as it should, and the machine images perfectly with the
# wrong name. It looks like the web UI dropped the field.
#
# So the imager states what it supports, and the web UI reads it back and warns
# when an assignment needs something this build does not have. Derived from
# `init` itself rather than hand-maintained: a list that has to be remembered is
# a list that goes stale exactly when it matters.
FEATURES="$(grep -oE 'getarg imager\.[a-z]+' "$HERE/init" \
            | sed 's/getarg imager\.//' | sort -u | tr '\n' ' ')"
printf '{"built":"%s","kernel":"%s","features":[%s]}\n' \
    "$(date -u +%FT%TZ)" "$KVER" \
    "$(printf '%s' "$FEATURES" | sed 's/ *$//; s/[^ ][^ ]*/"&"/g; s/ /,/g')" \
    > "$OUT/build.json"
log "Imager features: ${FEATURES:-none detected}"
rm -rf "$WORK"

log "Imager built:"
ls -lh "$OUT/vmlinuz" "$OUT/initramfs.img"
