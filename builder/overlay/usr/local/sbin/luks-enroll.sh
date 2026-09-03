#!/bin/bash
# First-boot LUKS enrollment, phase 1 of 2.
#
# The image ships with a bootstrap keyfile in the initramfs so the very first
# boot unlocks unattended. This service binds the LUKS volumes to the machine's
# TPM2 (or a Tang server) and switches the initramfs over to that -- but it does
# NOT destroy the bootstrap key. luks-enroll-reap.service does that, on the next
# boot, once the machine has actually come up through the new path.
#
# --- why it is split in two --------------------------------------------------
#
# The previous version bound the TPM and destroyed the keyfile in the same run,
# treating a zero exit from the enrolling command as proof the machine could
# still boot. It is not. `systemd-cryptenroll --tpm2-device=auto` writes a
# perfectly valid keyslot that Debian's initramfs-tools cannot use, because
# `tpm2-device=` is a systemd-cryptsetup option and this is not a systemd
# initrd -- so enrollment reported success, the only usable key was deleted, and
# the machine came up asking for a passphrase on a console nobody was watching.
# Both root slots and the overlay went at once, so there was no slot to fall
# back to and no recovery entry that helped: LUKS is unlocked long before the
# kernel command line means anything.
#
# The lesson is that the only proof that matters is a boot. So this phase makes
# every change that is reversible, proves what can be proved without rebooting,
# and leaves the bootstrap key in place; the next boot is the proof, and the
# reaper collects afterwards. A machine that fails anywhere in here still has
# its keyfile and still boots unattended.
set -u

CONF=/etc/luks-enroll.conf
STAMP=/var/lib/luks-enroll.done
PENDING=/var/lib/luks-enroll.pending
[ -f "$STAMP" ] && exit 0
[ -f "$PENDING" ] && exit 0     # phase 1 already done; the reaper has it now
[ -f "$CONF" ] || exit 0
# shellcheck disable=SC1090
. "$CONF"
METHOD="${METHOD:-}"
TANG_URL="${TANG_URL:-}"
# PCR 7 is the Secure Boot policy state: it does not move when the kernel or the
# initramfs changes, so a binding to it survives an A/B update. Binding to the
# PCRs that measure the boot chain itself (8, 9) would not -- and would also
# differ between the normal and recovery GRUB entries, which would quietly make
# the recovery entries the one thing that could not unlock.
TPM2_PCRS="${TPM2_PCRS:-7}"

log() { echo "luks-enroll: $*"; }

# Collect (name, device) pairs from crypttab.
mapfile -t ENTRIES < <(grep -vE '^\s*(#|$)' /etc/crypttab | awk '{print $1" "$2}')
[ "${#ENTRIES[@]}" -gt 0 ] || { log "no crypttab entries"; exit 0; }

# Any spelling crypttab allows, not just UUID=. Images now address the volumes
# by PARTLABEL so a bundle built from one image is installable on a machine
# imaged from another, and `blkid -U PARTLABEL=rootfs-a` finds nothing -- which
# would have shown up as enrollment silently skipping every volume, on a machine
# that then has no way to unlock itself unattended. UUID= stays handled: images
# built before the change are still out there and still run this script.
# Same resolution Debian's own _resolve_device_spec uses.
resolve() {
    case "$1" in
        UUID=*|LABEL=*|PARTUUID=*|PARTLABEL=*)
            blkid -l -t "$1" -o device 2>/dev/null;;
        *)  [ -b "$1" ] && printf '%s\n' "$1";;
    esac
}

case "$METHOD" in
    tpm2) PIN=tpm2; PIN_CFG="{\"pcr_bank\":\"sha256\",\"pcr_ids\":\"$TPM2_PCRS\"}";;
    tang) PIN=tang; PIN_CFG="{\"url\":\"$TANG_URL\"}";;
    *)    log "unknown METHOD=$METHOD"; exit 0;;
esac

# Both methods go through clevis. Tang always did; tpm2 used systemd-cryptenroll
# and that is exactly what did not work -- clevis ships an initramfs-tools hook
# (clevis-initramfs) and is the only one of the two that Debian's initramfs can
# actually call at unlock time.
for c in clevis cryptsetup lsinitramfs update-initramfs; do
    command -v "$c" >/dev/null 2>&1 || { log "$c is missing; cannot enroll"; exit 0; }
done

# `clevis luks pass` is how a binding is proved below. It has been in clevis
# since 12 and Debian is well past that, but an image built against something
# older should degrade to "verify less", not to "refuse to enroll" -- the boot
# that the reaper waits for is the real proof either way.
HAVE_PASS=0
if clevis luks pass 2>&1 | grep -qi 'usage.*clevis luks pass'; then HAVE_PASS=1
else log "note: this clevis has no 'luks pass'; relying on the staged boot alone"; fi

# --- bind ---------------------------------------------------------------------

enrolled_all=1
for e in "${ENTRIES[@]}"; do
    name="${e%% *}"; uuid="${e##* }"
    dev="$(resolve "$uuid")"
    kf="/etc/cryptsetup-keys.d/${name}.key"
    [ -b "$dev" ] || { log "cannot resolve device for $name; skipping"; enrolled_all=0; continue; }

    if clevis luks list -d "$dev" 2>/dev/null | grep -q "$PIN"; then
        log "$name already bound to $PIN"
    else
        [ -f "$kf" ] || { log "$name has no bootstrap key and no $PIN binding; skipping"; enrolled_all=0; continue; }
        log "binding $PIN for $name ($dev)"
        if clevis luks bind -y -k "$kf" -d "$dev" "$PIN" "$PIN_CFG"; then
            log "$PIN bound for $name"
        else
            log "$PIN bind FAILED for $name (will retry next boot)"; enrolled_all=0; continue
        fi
    fi

    # Prove the binding can actually be used, rather than that it was written.
    # `clevis luks pass` performs the real recovery -- unseal from the TPM, or
    # the round trip to Tang -- and returns the passphrase for that keyslot. It
    # is the same operation the initramfs will perform, minus the initramfs.
    # Its output IS key material, so it goes nowhere; only the exit status is
    # read.
    slot="$(clevis luks list -d "$dev" 2>/dev/null | awk -F: -v p="$PIN" '$0 ~ p {print $1; exit}')"
    if [ -z "$slot" ]; then
        log "  cannot find the $PIN keyslot for $name; not trusting this binding"
        enrolled_all=0; continue
    fi
    [ "$HAVE_PASS" = 1 ] || continue
    if clevis luks pass -d "$dev" -s "$slot" >/dev/null 2>&1; then
        log "  verified: $PIN recovers the key for $name (slot $slot)"
    else
        log "  VERIFY FAILED: $PIN cannot recover the key for $name"
        log "  (keeping the bootstrap keyfile; this machine still boots)"
        enrolled_all=0
    fi
done

if [ "$enrolled_all" != 1 ]; then
    log "not all volumes are verifiably bound; keeping the keyfile and retrying next boot"
    exit 0
fi

# --- switch the initramfs over ------------------------------------------------
#
# Everything below is reversible and is reverted on any failure, because the
# state it passes through -- an initramfs with no keyfile in it -- is the state
# that has to be right or the machine does not come up.

CRYPTTAB=/etc/crypttab
HOOKCONF=/etc/cryptsetup-initramfs/conf-hook
BACKUP=/var/lib/luks-enroll.backup
mkdir -p "$BACKUP"
cp -a "$CRYPTTAB" "$BACKUP/crypttab"
[ -f "$HOOKCONF" ] && cp -a "$HOOKCONF" "$BACKUP/conf-hook"

revert() {
    log "reverting to the bootstrap keyfile: $1"
    cp -a "$BACKUP/crypttab" "$CRYPTTAB"
    [ -f "$BACKUP/conf-hook" ] && cp -a "$BACKUP/conf-hook" "$HOOKCONF"
    update-initramfs -u >/dev/null 2>&1 || log "  WARNING: could not rebuild the initramfs"
    /usr/local/sbin/ab-sync-boot.sh --slot both >/dev/null 2>&1 || true
    log "  the machine still unlocks with its keyfile; will retry next boot"
    exit 0
}

# Point crypttab at clevis: no keyfile, and no tpm2-device= either. That option
# is what the old code wrote and it means nothing to initramfs-tools; clevis
# hooks the passphrase prompt instead, so the correct spelling is a plain entry
# with `none` where the keyfile was.
sed -i -E 's#(^\s*\S+\s+\S+\s+)/etc/cryptsetup-keys\.d/\S+#\1none#' "$CRYPTTAB"
sed -i -E 's#,tpm2-device=auto##' "$CRYPTTAB"
sed -i '/KEYFILE_PATTERN/d' "$HOOKCONF" 2>/dev/null || true

update-initramfs -u || revert "update-initramfs failed"

# update-initramfs writes the versioned file at the top of /boot; ab-sync-boot
# below is what puts it where GRUB looks. Check it before it is copied anywhere.
NEW_INITRD="/boot/initrd.img-$(uname -r)"

# The two things that were wrong last time, asked directly of the artefact that
# will be booted: can it unlock without a keyfile, and is the keyfile really out
# of it? An initramfs with no clevis in it is the exact failure this whole
# rewrite exists to prevent, and it is one grep away.
lsinitramfs "$NEW_INITRD" 2>/dev/null | grep -qE 'clevis-luks-askpass|scripts/local-top/clevis' \
    || revert "the new initramfs contains no clevis unlock hook (is clevis-initramfs installed?)"
if [ "$METHOD" = tpm2 ]; then
    lsinitramfs "$NEW_INITRD" 2>/dev/null | grep -qi 'tss2\|tpm2' \
        || revert "the new initramfs contains no TPM2 libraries"
fi
lsinitramfs "$NEW_INITRD" 2>/dev/null | grep -q 'cryptsetup-keys\.d' \
    && revert "the new initramfs still embeds the bootstrap keyfile"

# Both slots, not just this one. The reaper removes the bootstrap keyslot from
# every volume in crypttab -- including the other slot's root -- so an initramfs
# left behind in the other slot's directory would be one holding a keyfile that
# no longer opens anything. That is how the other slot used to die silently.
/usr/local/sbin/ab-sync-boot.sh --slot both || revert "could not update the slot's initramfs copy"

: > "$PENDING"
log "bound and staged. The NEXT boot unlocks via $PIN with no keyfile;"
log "if it succeeds, luks-enroll-reap destroys the bootstrap key then."
log "Until then this machine can still be opened with its recovery passphrase."
systemctl disable luks-enroll.service >/dev/null 2>&1 || true
exit 0
