#!/bin/bash
#
# Turn a built A/B image into a signed RAUC update bundle.
#
# This is the piece that makes the two slots worth having. Without it the only
# way to patch a machine is to re-image it, which is what the A/B layout exists
# to avoid: an update writes the *inactive* slot while the machine keeps running
# on the active one, flips the boot order, and reboots. If the new slot does not
# come up, GRUB's try-counter falls back to the old one on its own.
#
# What goes in the bundle is the root slot only. /boot, the ESP and the overlay
# are deliberately left alone: the overlay is the machine's data and identity,
# and destroying it on update is the bug this project already fixed once.
#
#   ./make-bundle.sh --image /output/debian-trixie-ab.img [--version 2026.08.03]
#
# Runs inside the builder container (it needs rauc, loop devices, and root).
set -euo pipefail

IMAGE=""
VERSION=""
OUTPUT=""
COMPATIBLE=""
KEYDIR="${KEYDIR:-/output/rauc-keys}"
LUKS_PASS="${LUKS_PASS:-}"              # only needed for an encrypted source image
MAPNAME="ab-bundle-src"
DESCRIPTION=""

log()  { echo -e "\033[0;32m[bundle]\033[0m $*"; }
die()  { echo -e "\033[0;31m[bundle] ERROR:\033[0m $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --image)       IMAGE="$2"; shift 2;;
        --version)     VERSION="$2"; shift 2;;
        --output)      OUTPUT="$2"; shift 2;;
        --compatible)  COMPATIBLE="$2"; shift 2;;
        --description) DESCRIPTION="$2"; shift 2;;
        --keydir)      KEYDIR="$2"; shift 2;;
        --luks-passphrase) LUKS_PASS="$2"; shift 2;;
        -h|--help) sed -n '2,20p' "$0"; exit 0;;
        *) die "unknown option '$1'";;
    esac
done

[ -n "$IMAGE" ] || die "--image is required"
[ -f "$IMAGE" ] || die "no such image: $IMAGE"

WORK="$(mktemp -d)"

# A compressed image is decompressed first rather than refused. The root slot
# has to be mounted out of the image, which cannot be done through zstd or gzip
# -- but that is a reason to decompress, not a reason to make people rebuild an
# image they already have. Most images this project produces are compressed,
# so refusing them made the update path unreachable for the common case.
case "$IMAGE" in
    *.img.zst|*.zst)
        log "Decompressing $(basename "$IMAGE") (compressed images cannot be mounted directly)"
        command -v zstd >/dev/null || die "zstd is not available to decompress $IMAGE"
        zstd -d -q -o "$WORK/source.img" "$IMAGE" || die "could not decompress $IMAGE"
        IMAGE="$WORK/source.img"
        ;;
    *.img.gz|*.gz)
        log "Decompressing $(basename "$IMAGE")"
        gzip -dc "$IMAGE" > "$WORK/source.img" || die "could not decompress $IMAGE"
        IMAGE="$WORK/source.img"
        ;;
esac
VERSION="${VERSION:-$(date -u +%Y.%m.%d-%H%M)}"
# The version ends up in three places that all have opinions about characters: a
# filename, RAUC's manifest, and a single-quoted assignment inside the generated
# install hook. Constrained once, here, rather than escaped three times -- and a
# quote in a version string would break the hook on the machine, at install
# time, which is the worst place to find out.
case "$VERSION" in
    *[!A-Za-z0-9.+:~_-]*) die "--version may only contain letters, digits and . + : ~ _ - \
(got '$VERSION')";;
esac

# --- signing key -------------------------------------------------------------
#
# Generated once and kept, because the certificate has to be inside every image
# that will ever accept a bundle signed by it -- rotating the key orphans every
# machine already deployed. build-image.sh installs $KEYDIR/cert.pem into the
# image's keyring, so keys must exist before the images that trust them.
mkdir -p "$KEYDIR"
if [ ! -f "$KEYDIR/key.pem" ] || [ ! -f "$KEYDIR/cert.pem" ]; then
    log "Generating a signing key in $KEYDIR (keep it: images trust this cert)"
    openssl req -x509 -newkey rsa:4096 -nodes -sha256 -days 3650 \
        -keyout "$KEYDIR/key.pem" -out "$KEYDIR/cert.pem" \
        -subj "/O=flipside/CN=A-B Update Signing" 2>/dev/null
    chmod 600 "$KEYDIR/key.pem"
fi

cleanup() {
    mountpoint -q "$WORK/slot" 2>/dev/null && umount "$WORK/slot" || true
    cryptsetup close "$MAPNAME" 2>/dev/null || true
    [ -n "${LOOP:-}" ] && losetup -d "$LOOP" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

log "Reading root slot A from $(basename "$IMAGE")"
LOOP="$(losetup -f --show -P "$IMAGE")"
# udev does not run in the builder container, so the partition nodes the kernel
# knows about have to be created by hand from sysfs.
BB="$(basename "$LOOP")"
for n in $(ls /sys/class/block/ 2>/dev/null | sed -n "s/^${BB}p//p" | sort -n); do
    IFS=: read -r mj mn < "/sys/class/block/${BB}p${n}/dev"
    rm -f "/dev/${BB}p${n}"; mknod "/dev/${BB}p${n}" b "$mj" "$mn"
done

SLOT_PART=""
for n in $(ls /sys/class/block/ 2>/dev/null | sed -n "s/^${BB}p//p" | sort -n); do
    dev="/dev/${BB}p${n}"
    if [ "$(sgdisk -i "$n" "$LOOP" 2>/dev/null | sed -n 's/^Partition name: .\(.*\).$/\1/p')" = "rootfs-a" ]; then
        SLOT_PART="$dev"; break
    fi
done
[ -n "$SLOT_PART" ] || die "could not find the rootfs-a partition in $IMAGE"

mkdir -p "$WORK/slot" "$WORK/bundle"

# An encrypted image keeps the filesystem inside a LUKS container, so the slot
# has to be opened before it can be read. Only the builder needs the passphrase:
# what goes into the bundle is the plain filesystem, and the machine installing
# it writes into its own already-unlocked slot. So a bundle built from an
# encrypted image is not itself encrypted, and installs on encrypted and
# unencrypted machines alike.
if cryptsetup isLuks "$SLOT_PART" 2>/dev/null; then
    [ -n "$LUKS_PASS" ] || die "this image is encrypted; pass --luks-passphrase (or set
  LUKS_PASS) so the root slot can be read. The passphrase is used here only, and
  is not stored in the bundle."
    printf '%s' "$LUKS_PASS" | cryptsetup open --readonly "$SLOT_PART" "$MAPNAME" - 2>/dev/null \
        || die "the LUKS passphrase did not unlock the root slot"
    SLOT_PART="/dev/mapper/$MAPNAME"
    log "Opened the encrypted root slot"
fi

mount -o ro "$SLOT_PART" "$WORK/slot" || die "could not mount the root slot"

# The kernel and initramfs come from the source image's BOOT partition, not from
# the root slot -- /boot is a separate filesystem, so it is an empty mountpoint
# inside the slot. Carrying them means an update can deliver a new kernel; the
# post-install hook writes them to the target slot's directory only, leaving the
# running slot's kernel alone so rollback still lands somewhere that boots.
BOOT_PART=""
for n in $(ls /sys/class/block/ 2>/dev/null | sed -n "s/^${BB}p//p" | sort -n); do
    if [ "$(sgdisk -i "$n" "$LOOP" 2>/dev/null | sed -n 's/^Partition name: .\(.*\).$/\1/p')" = "BOOT" ]; then
        BOOT_PART="/dev/${BB}p${n}"; break
    fi
done
if [ -n "$BOOT_PART" ]; then
    mkdir -p "$WORK/bootsrc" "$WORK/bundle"
    if mount -o ro "$BOOT_PART" "$WORK/bootsrc" 2>/dev/null; then
        _kv="$(ls "$WORK/bootsrc" | sed -n 's/^vmlinuz-//p' | head -1)"
        if [ -n "$_kv" ]; then
            mkdir -p "$WORK/bootfiles"
            cp "$WORK/bootsrc/vmlinuz-$_kv"    "$WORK/bootfiles/vmlinuz"
            cp "$WORK/bootsrc/initrd.img-$_kv" "$WORK/bootfiles/initrd.img"
            log "Including kernel $_kv in the bundle"
        else
            log "WARNING: no kernel on the source image's BOOT partition; the bundle"
            log "         will update userspace only"
        fi
        umount "$WORK/bootsrc"
    fi
fi

if [ -z "$COMPATIBLE" ]; then
    COMPATIBLE="$(sed -n 's/^compatible=//p' "$WORK/slot/etc/rauc/system.conf" 2>/dev/null | head -1)"
fi
[ -n "$COMPATIBLE" ] || die "could not read 'compatible' from the image's rauc/system.conf"
log "compatible=$COMPATIBLE  version=$VERSION"

# The writable-state layout this bundle carries. `compatible` does not cover it:
# RAUC will happily install a bundle whose state.conf declares a different model
# or a different upper mode, and the machine then refuses it at boot -- correctly,
# because applying it would hide everything the machine has written. That refusal
# reaches only the kernel log of a machine that just failed to come up, so say it
# here, where whoever is building the bundle can still act on it.
_st="$WORK/slot/usr/lib/ab/state.conf"
if [ -r "$_st" ]; then
    _model="$(awk '$1=="model"{print $2; exit}' "$_st")"
    _upper="$(awk '$1=="upper"{print $2; exit}' "$_st")"
    [ -n "$_upper" ] || _upper=shared
    _layout="${_model:-overlay}"
    [ "$_upper" = per-slot ] && _layout="$_layout+per-slot-upper"
    log "state layout=$_layout  (installs only on machines imaged with this layout)"
fi

# RAUC verifies the bundle against the running system's `compatible`, which is
# what stops a Debian bundle being installed onto an Ubuntu machine.
# A tar, not a filesystem image. RAUC picks its update handler from the image's
# file extension and the slot type: for an ext4 slot a .tar* is "make a fresh
# filesystem and extract into it", which is what an A/B root update should be.
# A squashfs is rejected outright -- "Unsupported image rootfs.squashfs for slot
# type ext4" -- and a raw ext4 image would tie the bundle to one slot size.
#
# --numeric-owner because the bundle is unpacked on a machine whose passwd file
# is not consulted; --xattrs to carry capabilities (ping, etc.) across.
#
# squashfs-tools is still required in the builder even though the payload is a
# tar: rauc builds the bundle container itself with mksquashfs.
# No LUKS key material in a bundle, ever. Bundles are published over plain HTTP
# for any machine to fetch, and an image built before the key moved to the BOOT
# partition keeps it in /etc/cryptsetup-keys.d -- so bundling one of those used
# to put the keys to its own disks on a web server. Excluded rather than
# refused: the bundle is still perfectly installable without them, because the
# machine gets its key from its own BOOT partition.
if [ -n "$(ls -A "$WORK/slot/etc/cryptsetup-keys.d" 2>/dev/null)" ]; then
    log "NOTE: this image carries LUKS keyfiles in /etc/cryptsetup-keys.d."
    log "      They are being left out of the bundle -- a bundle is published,"
    log "      and key material has no business in one. Rebuild the image to"
    log "      keep the key on the BOOT partition where an update cannot reach it."
fi

# What this bundle will put on a machine. Generated from the mounted slot for
# the same reason the image's is: this is the only moment the package list can
# be read. It matters more here than for the image, because an update is what
# *changes* what a machine is running -- an SBOM per image and none per bundle
# would describe the fleet as it was first provisioned and never since.
#
# Written beside the bundle rather than into it. A bundle is a signed artifact
# whose contents are covered by that signature, and adding a file to it means
# either signing the SBOM's own hash into the manifest or shipping something the
# signature does not cover. Beside it, alongside the .json and .sha256 sidecars
# that are already there, is the honest place for it.
if [ -x "$(dirname "$0")/make-sbom.sh" ]; then
    log "Recording what this bundle installs (SBOM)"
    OUTPUT_PRE="${OUTPUT:-/output/bundles/${COMPATIBLE}-${VERSION}.raucb}"
    mkdir -p "$(dirname "$OUTPUT_PRE")"
    "$(dirname "$0")/make-sbom.sh" --root "$WORK/slot" --out "$OUTPUT_PRE" \
        --name "$(basename "${OUTPUT_PRE%.raucb}")" --version "$VERSION" \
        --distro "${COMPATIBLE%%-*}" --arch "$(dpkg --print-architecture)" >/dev/null \
        || log "NOTE: no SBOM was generated for this bundle; the bundle itself is fine."
fi

log "Packing the root slot (this is the slow part)"
tar --numeric-owner --xattrs --xattrs-include='*' \
    --warning=no-file-ignored --warning=no-file-changed \
    --exclude='./etc/cryptsetup-keys.d/*' \
    -C "$WORK/slot" -czf "$WORK/bundle/rootfs.tar.gz" .

# RAUC makes a fresh filesystem in the target slot, and a fresh ext4 has no
# label. GRUB boots by root=LABEL=rootfs-a|b, so without this the updated slot
# comes up as "ALERT! LABEL=rootfs-b does not exist" and drops to an initramfs
# shell -- the update installs perfectly and then bricks the boot.
#
# A post-install hook rather than extra-mkfs-opts in system.conf: the hook works
# on every RAUC version, and it runs on the machine, so it labels whichever slot
# was actually written rather than whatever the bundle guessed.
#
# The version is baked in here rather than written into the source slot, because
# that slot is mounted read-only (line "mount -o ro" above) -- and a `printf >`
# into a read-only mount fails at the moment the whole update path depends on
# it. It could not be made writable either: the mount is the *source image*, and
# a bundle build has no business modifying the image it was built from.
{
    echo '#!/bin/sh'
    echo 'set -e'
    printf "BUNDLE_VERSION='%s'\n" "$VERSION"
    cat <<'HOOK'
case "$1" in
    slot-post-install)
        case "$RAUC_SLOT_BOOTNAME" in
            A) label=rootfs-a;;
            B) label=rootfs-b;;
            *) exit 0;;
        esac
        e2label "$RAUC_SLOT_DEVICE" "$label"

        # The kernel for this slot, if the bundle carries one. Written under
        # /boot/<A|B>/ so only the slot just updated changes: the running slot
        # keeps the kernel it booted, which is what a rollback needs.
        mkdir -p "/boot/$RAUC_SLOT_BOOTNAME"
        if [ -f "$RAUC_BUNDLE_MOUNT_POINT/boot.tar.gz" ]; then
            tar -C "/boot/$RAUC_SLOT_BOOTNAME" -xzf "$RAUC_BUNDLE_MOUNT_POINT/boot.tar.gz"
            sync
            echo "installed kernel for slot $RAUC_SLOT_BOOTNAME"
        fi

        # What this slot now is, beside the kernel that boots it. The control
        # plane's whole notion of "did this machine take the update" rests on
        # the machine being able to name the version it is running -- nothing
        # else on a booted system records which bundle wrote its root slot, and
        # os-release names the Debian release, which every build shares.
        #
        # Per-slot, under /boot, for the same reason the kernel is: a rollback
        # lands on the other slot, which keeps its own file, so the machine
        # reports the version it actually rolled back to instead of insisting it
        # is still on the one that failed.
        printf '%s\n' "$BUNDLE_VERSION" > "/boot/$RAUC_SLOT_BOOTNAME/ab-version"
        sync
        ;;
esac
exit 0
HOOK
} > "$WORK/bundle/hook.sh"
chmod +x "$WORK/bundle/hook.sh"

cat > "$WORK/bundle/manifest.raucm" <<EOF
[bundle]
# verity, not plain. RAUC installs straight from an HTTP URL by streaming, and
# streaming refuses a plain bundle outright -- "Bundle format 'plain' not
# supported in streaming mode" -- so a plain bundle can only be installed from a
# file already on the machine. verity has been supported since RAUC 1.5, which
# covers every suite this builder targets. ab-update falls back to downloading
# first if a machine ever does refuse to stream.
format=verity

[update]
compatible=${COMPATIBLE}
version=${VERSION}
description=${DESCRIPTION:-A/B root filesystem update}

[hooks]
filename=hook.sh

[image.rootfs]
filename=rootfs.tar.gz
hooks=post-install
EOF

umount "$WORK/slot"
cryptsetup close "$MAPNAME" 2>/dev/null || true

if [ -f "$WORK/bootfiles/vmlinuz" ]; then
    tar -C "$WORK/bootfiles" -czf "$WORK/bundle/boot.tar.gz" .
fi

OUTPUT="${OUTPUT:-/output/bundles/${COMPATIBLE}-${VERSION}.raucb}"
mkdir -p "$(dirname "$OUTPUT")"
rm -f "$OUTPUT"

# Built into the container's own filesystem and copied out afterwards, rather
# than written straight to /output. RAUC refuses to read a 'plain' bundle from a
# filesystem it does not recognise -- a guard against the bundle changing under
# it mid-install -- and /output is a bind mount, which on some hosts (Docker
# Desktop's virtiofs, for one) is exactly that. Verification would fail there on
# a bundle that is perfectly good.
STAGED="$WORK/staged.raucb"
log "Signing the bundle"
rauc bundle --cert="$KEYDIR/cert.pem" --key="$KEYDIR/key.pem" \
    "$WORK/bundle" "$STAGED"

# Verify against the certificate machines will carry, rather than trusting that
# signing succeeded. This is the check RAUC performs on the machine itself, so a
# bundle failing here would have failed there.
log "Verifying the bundle against the keyring machines will use"
rauc info --keyring="$KEYDIR/cert.pem" "$STAGED" >/dev/null 2>&1 \
    || die "the finished bundle does not verify against $KEYDIR/cert.pem"

mv "$STAGED" "$OUTPUT"

# The sidecar is what the web UI reads to list bundles without unpacking them.
cat > "${OUTPUT}.json" <<EOF
{"version":"${VERSION}","compatible":"${COMPATIBLE}","source":"$(basename "$IMAGE")",
 "created":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","description":"${DESCRIPTION:-A/B root filesystem update}"}
EOF
sha256sum "$OUTPUT" | awk '{print $1}' > "${OUTPUT}.sha256"

# A pointer to the newest bundle, so `ab-update` with no arguments has something
# to ask for. Directory listing is off on the HTTP server (and parsing an index
# would be a poor contract anyway), so the newest build states it explicitly.
basename "$OUTPUT" > "$(dirname "$OUTPUT")/latest"

log "Bundle built: $OUTPUT"
ls -lh "$OUTPUT" | awk '{print "  " $9 "  " $5}'
log "Install it on a machine with:"
echo "    rauc install http://<server>/bundles/$(basename "$OUTPUT")"
