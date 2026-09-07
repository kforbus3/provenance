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
    inst_multiple blkid mount umount cp mkdir chmod

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
    mkdir -p "${initdir}/lib/dracut/hooks/initqueue/settled"
    {
        echo '#!/bin/sh'
        echo '/usr/lib/ab/initramfs/ab-luks-key'
    } > "${initdir}/lib/dracut/hooks/initqueue/settled/10-ab-luks-key.sh"
    chmod 0755 "${initdir}/lib/dracut/hooks/initqueue/settled/10-ab-luks-key.sh"

    # The marker the enrolment reaper reads, written only when crypttab still
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
