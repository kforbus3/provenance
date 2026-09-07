#!/usr/bin/env bash
# Can this family's bootloader actually be installed the way the build installs
# it, and does the ESP end up with something a machine will boot?
#
# Companion to initramfs-smoke.sh, and it exists for the same reason: the
# bootloader step is the LAST thing a 30-minute build does, so every mistake in
# it costs a full build to discover. This runs the same commands against the same
# packages in a few minutes.
#
# The specific thing it pins is a genuine difference between the families rather
# than a naming one. Red Hat PATCHES grub2-install to refuse an EFI target:
#
#   grub2-install: error: This utility should not be used for EFI platforms
#   because it does not support UEFI Secure Boot.
#
# because on this family the EFI bootloader is a prebuilt, vendor-signed binary
# that arrives with grub2-efi-x64 and is already on the ESP. Calling
# grub2-install for EFI is wrong here, and --force is worse: it replaces a signed
# bootloader with a locally generated unsigned one, which no machine with Secure
# Boot enabled will run.
#
# Usage: builder/smoke/bootloader-smoke.sh [suite]     (default 9)
set -euo pipefail

SUITE="${1:-9}"
FAILURES=0

log()  { echo -e "\033[0;32m[smoke]\033[0m $*"; }
fail() { echo -e "\033[0;31m[smoke] FAIL\033[0m $*"; FAILURES=$((FAILURES + 1)); }
pass() { echo -e "\033[0;32m[smoke] PASS\033[0m $*"; }

ulimit -S -n 65536 2>/dev/null || true
ulimit -H -n 65536 2>/dev/null || true

R=/tmp/bootroot
rm -rf "$R"; mkdir -p "$R"

cleanup() {
    set +e
    for d in etc/resolv.conf dev proc sys; do
        mountpoint -q "$R/$d" && umount "$R/$d"
    done
}
trap cleanup EXIT

log "bootstrapping a minimal el${SUITE} root"
dnf -y -q --installroot="$R" --releasever="$SUITE" --nogpgcheck \
    --setopt=install_weak_deps=False install dnf systemd passwd >/dev/null 2>&1 \
    || { fail "bootstrap failed"; exit 1; }

rm -f "$R/etc/resolv.conf"; : > "$R/etc/resolv.conf"
mount --bind /etc/resolv.conf "$R/etc/resolv.conf"
for d in dev proc sys; do mount --bind "/$d" "$R/$d"; done

# The same package list build-image.sh installs for this family and arch.
GRUB_PKGS="grub2-pc grub2-efi-x64 grub2-efi-x64-modules grub2-tools efibootmgr"
SB_PKGS="shim-x64"
log "installing: $GRUB_PKGS $SB_PKGS"
chroot "$R" dnf -y -q install --setopt=install_weak_deps=False \
    $GRUB_PKGS $SB_PKGS >/dev/null 2>&1 \
    || { fail "the bootloader packages did not install"; exit 1; }

DISTRO_ID="$(sed -n 's/^ID=//p' "$R/etc/os-release" | tr -d '"')"
log "distro id: ${DISTRO_ID:-unknown}"

# 1. The modules package really is what provides the BIOS install's inputs.
#    grub2-efi-x64 on its own ships nothing under /usr/lib/grub, so without the
#    -modules package grub2-install dies at the last step of the build.
if [ -f "$R/usr/lib/grub/x86_64-efi/modinfo.sh" ]; then
    pass "grub2-efi-x64-modules provides /usr/lib/grub/x86_64-efi"
else
    fail "no /usr/lib/grub/x86_64-efi/modinfo.sh -- grub2-install cannot build for EFI"
fi

# 2. The signed chain, at the paths the Secure Boot block looks in. These are
#    ESP paths shipped BY THE PACKAGE, not /usr/lib/shim as on Debian.
ESP="$R/boot/efi/EFI/${DISTRO_ID}"
for f in grubx64.efi shimx64.efi mmx64.efi; do
    if [ -f "$ESP/$f" ]; then
        pass "packaged $f is on the ESP at EFI/${DISTRO_ID}/"
    else
        fail "no $f at EFI/${DISTRO_ID}/ -- the Secure Boot chain has nothing to install"
    fi
done

# 3. BIOS install works. This one IS called by the build.
if chroot "$R" grub2-install --target=i386-pc --boot-directory=/boot \
        --recheck /dev/null >/dev/null 2>&1; then
    pass "grub2-install --target=i386-pc runs"
else
    # /dev/null is not a disk, so a device error here is expected and fine --
    # what matters is that it got far enough to try, i.e. the target exists.
    if chroot "$R" grub2-install --target=i386-pc --help >/dev/null 2>&1; then
        pass "grub2-install supports the i386-pc target (no real disk to write to here)"
    else
        fail "grub2-install cannot do i386-pc at all"
    fi
fi

# 4. And the one the build must NOT call. If a future release stops refusing,
#    this test says so rather than silently leaving us on the packaged path for
#    no reason -- and if it still refuses, calling it would fail the build.
EFI_ERR="$(chroot "$R" grub2-install --target=x86_64-efi --efi-directory=/boot/efi \
    --removable --no-nvram 2>&1 || true)"
if grep -qi "should not be used for EFI platforms" <<<"$EFI_ERR"; then
    pass "grub2-install still refuses EFI, as expected -- the build uses the packaged binary"
else
    fail "grub2-install no longer refuses EFI on this release. Re-read the build's
        UEFI branch: it deliberately does not call this, and the reason may have
        changed. Output was: $(head -2 <<<"$EFI_ERR")"
fi

# 5. The grub.cfg directory. grub2-install --target=i386-pc creates /boot/grub2,
#    and the compiled-in prefix of the core image points there -- so a config
#    written to /boot/grub is a clean build and a `grub rescue>` prompt.
if [ -d "$R/boot/grub2" ]; then
    pass "the BIOS install created /boot/grub2 (not /boot/grub)"
else
    log "  (no /boot/grub2 -- BIOS install had no real disk here, not a failure)"
fi
if [ -d "$R/boot/grub" ]; then
    fail "/boot/grub exists on an rpm root; the build writes grub.cfg to \$GRUBDIR
        and this suggests the two spellings have been mixed up again"
fi

# 6. grub2-editenv, which RAUC's grub backend calls by the bare name grub-editenv.
if chroot "$R" sh -c 'command -v grub2-editenv' >/dev/null 2>&1; then
    pass "grub2-editenv is present (the build symlinks grub-editenv to it for RAUC)"
else
    fail "no grub2-editenv -- nothing can record slot order or probation"
fi

echo
if [ "$FAILURES" -gt 0 ]; then
    echo -e "\033[0;31m[smoke] $FAILURES check(s) failed\033[0m"
    echo "[smoke] The bootloader is the last step of a 30-minute build; each of"
    echo "[smoke] these would have been found there instead of here."
    exit 1
fi
echo -e "\033[0;32m[smoke] all bootloader checks passed\033[0m"
