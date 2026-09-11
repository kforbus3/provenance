#!/bin/bash
# This machine's LUKS bootstrap key, for dracut.
#
# Counterpart of etc/initramfs-tools/hooks/ab-luks-key. The key lives on the BOOT
# partition rather than inside the image, because an update replaces the root
# slot AND the initramfs generated from it -- a key baked into the image is the
# builder's key, not this machine's. See the script itself for the failure that
# taught us that.

check() {
    # The state manifest is the marker that this is one of our images. Adding an
    # overlay root to somebody else's initramfs would be a surprising thing to do,
    # and dracut runs every module's check() on every host it is installed on.
    [ -f /usr/lib/ab/state.conf ] && return 0
    return 255
}

depends() {
    echo "crypt"
    return 0
}

install() {
    # blkid is what the script finds the BOOT partition with, by label, and it is
    # not otherwise guaranteed in a minimal initramfs.
    # Every binary the script calls, checked against the script rather than
    # remembered. A dracut initramfs is not a distribution: a command not named
    # here is simply absent, and the failure is a shell error in the middle of an
    # unlock rather than anything that says "missing package". `dirname` was
    # absent exactly this way and cost a machine its unattended boot -- the hook
    # ran, printed "dirname: command not found", made no keyfile, and the disk
    # fell through to a passphrase prompt.
    inst_multiple blkid mount umount cp mkdir chmod grep head sleep
    inst_multiple -o udevadm

    # initqueue/settled, not pre-mount or pre-trigger.
    #
    # The key has to be in place before dracut's crypt module asks for a
    # passphrase, and the script finds the BOOT partition with blkid -- which
    # needs the block devices to exist. pre-trigger is too early (udev has not
    # enumerated anything yet, so blkid finds nothing and every boot would fall
    # back to prompting); pre-mount is too late (the root device, and therefore
    # the unlock, is what the initqueue is already waiting for).
    #
    # settled is the point where both are true: devices are enumerated, and the
    # initqueue is still retrying the unlock it has not managed yet.
    #
    # A wrapper ending in .sh, not inst_hook: dracut sources only *.sh from a
    # hook directory, and inst_hook would install this as "10ab-luks-key" -- in
    # the image and never executed, so every encrypted machine fell back to
    # prompting for a passphrase that nobody was there to type. The wrapper runs
    # the script as a child because it exits 0 on its ordinary paths, and
    # sourcing that would end dracut's init. See 90ab-overlay for the same note.
    inst_script /usr/lib/ab/initramfs/ab-luks-key /usr/lib/ab/initramfs/ab-luks-key

    # A systemd unit ordered Before=cryptsetup-pre.target, because the hook alone
    # runs too late.
    #
    # In a systemd initrd the cryptsetup units start as their devices appear, and
    # a non-root volume is asked for exactly ONCE. rootfs-a and the overlay are
    # retried by the root-device target and so survived the race; rootfs-b fired
    # first, found no keyfile, and fell straight through to a passphrase prompt --
    # on a machine that had the right key on its own BOOT partition the entire
    # time. The keyslots were correct, the key was correct, the hook was correct:
    # only the ordering was wrong, which is why every check of the image passed.
    #
    # cryptsetup-pre.target is systemd's ordering point for work that must finish
    # before ANY cryptsetup unit runs. This removes the race rather than making it
    # less likely.
    if [ -n "${systemdsystemunitdir:-}" ]; then
        inst_simple "$moddir/ab-luks-key.service" \
            "$systemdsystemunitdir/ab-luks-key.service"
        mkdir -p "${initdir}${systemdsystemunitdir}/sysinit.target.wants"
        ln -sf ../ab-luks-key.service \
            "${initdir}${systemdsystemunitdir}/sysinit.target.wants/ab-luks-key.service"
    fi

    # The initqueue hook stays as well. It costs nothing -- the script is
    # idempotent and exits immediately once the key is staged -- and it is the
    # only path on a dracut built without systemd, where the unit above is never
    # installed at all.
    mkdir -p "${initdir}/lib/dracut/hooks/initqueue/settled"
    {
        echo '#!/bin/sh'
        echo '/usr/lib/ab/initramfs/ab-luks-key'
    } > "${initdir}/lib/dracut/hooks/initqueue/settled/10-ab-luks-key.sh"
    chmod 0755 "${initdir}/lib/dracut/hooks/initqueue/settled/10-ab-luks-key.sh"

    # The marker the enrollment reaper reads, written only when crypttab still
    # points at the bootstrap key -- exactly when the hook above does anything.
    # luks-enroll.sh rewrites crypttab to clevis and rebuilds, which drops the
    # marker, and that next boot is the proof the reaper waits for before
    # destroying the bootstrap keyslot.
    if grep -qs '/cryptkey/luks\.key' /etc/crypttab; then
        mkdir -p "${initdir}/cryptkey"
        chmod 0700 "${initdir}/cryptkey"
        : > "${initdir}/cryptkey/bootstrap-key-in-use"
    fi
}
