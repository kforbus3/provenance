#!/bin/bash
# The A/B overlay root, for dracut.
#
# This is the counterpart of etc/initramfs-tools/hooks/ab-overlay: it puts into
# the initramfs what /usr/lib/ab/initramfs/ab-overlay needs at boot, and hooks
# that script at the point where the root slot is mounted but not yet switched
# to. The script itself is shared between the two harnesses -- see the note at
# the top of it -- because it is what decides whether a machine's writable state
# exists, and two copies would diverge exactly once.

check() {
    # Always available when explicitly asked for, and included by default only
    # when this really is an A/B image. The manifest is the marker: an image
    # without one is not one of ours, and adding an overlay root to somebody
    # else's initramfs would be a surprising thing to do.
    # The state manifest is the marker that this is one of our images. Adding an
    # overlay root to somebody else's initramfs would be a surprising thing to do,
    # and dracut runs every module's check() on every host it is installed on.
    [ -f /usr/lib/ab/state.conf ] && return 0
    return 255
}

depends() {
    # dm and crypt bring the device-mapper plumbing the overlay volume arrives
    # on when the image is encrypted. Listing them costs nothing on an
    # unencrypted image and is the difference between working and not on an
    # encrypted one.
    echo "dm crypt"
    return 0
}

installkernel() {
    # Without the overlay module there is no overlay root, and the failure is a
    # machine that boots read-only with nothing in the log to say why.
    instmods overlay
}

install() {
    # rm, cp and blkid are NOT optional, and none of them is guaranteed present.
    #
    # This is the same trap the initramfs-tools hook documents: klibc ships
    # `nuke` rather than `rm`, so every `rm -rf` in the overlay script failed
    # silently for months and an A/B update left the previous release's /usr
    # shadowing the one just installed. dracut's busybox-less initramfs has the
    # same shape of problem, so they are installed explicitly rather than hoped
    # for.
    inst_multiple rm cp mkdir mount umount blkid findmnt
    inst_multiple -o modprobe

    # pre-pivot: the root slot is mounted at $NEWROOT and we have not switched to
    # it. That is exactly initramfs-tools' local-bottom, which is where the same
    # script runs on the other family.
    #
    # 90, so it runs after anything that assembles the devices the overlay lives
    # on and before the ordinary cleanup hooks.
    #
    # NOT inst_hook, and the reason is not style. inst_hook names the installed
    # file "<prio><basename>" -- here "90ab-overlay" -- while dracut's hook runner
    # sources only files matching *.sh. The hook was installed into every image
    # and never once ran: no overlay root, no slot selection, and a build that
    # reported success because "ab-overlay" appears in lsinitrd's module list
    # whether or not anything executes it.
    #
    # A wrapper that EXECUTES rather than a script renamed to *.sh, because hooks
    # are sourced: this script calls `exit 0` on its ordinary paths (booting the
    # slot directly, overlay disabled on the cmdline), and sourcing that would
    # end dracut's init instead of the script. Running it as a child keeps its
    # exit status its own. The shared script also cannot simply be renamed --
    # initramfs-tools skips run-parts filenames containing a dot, so a .sh suffix
    # would break the other family.
    inst_script /usr/lib/ab/initramfs/ab-overlay /usr/lib/ab/initramfs/ab-overlay
    mkdir -p "${initdir}/lib/dracut/hooks/pre-pivot"
    {
        echo '#!/bin/sh'
        echo '/usr/lib/ab/initramfs/ab-overlay'
    } > "${initdir}/lib/dracut/hooks/pre-pivot/90-ab-overlay.sh"
    chmod 0755 "${initdir}/lib/dracut/hooks/pre-pivot/90-ab-overlay.sh"
}
