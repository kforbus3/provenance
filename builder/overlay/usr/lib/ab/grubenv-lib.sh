# Where GRUB's environment block is, and what the tool to edit it is called.
#
# Sourced by every script that touches grubenv on a running machine. It exists
# because the two distribution families disagree on both names and the scripts
# that ship inside the image cannot be templated at build time -- they are copied
# in verbatim and must work on whichever family they land on.
#
#   Debian/Ubuntu:  /boot/grub/grubenv    grub-editenv
#   RHEL family:    /boot/grub2/grubenv   grub2-editenv
#
# Hard-coding Debian's spellings, which is what these scripts used to do, is not
# a cosmetic bug on the other family. ab-slot-pending is RAUC's post-install
# handler and swallows its own failures by design, so every update installed
# "successfully" with no probation armed and no try counter -- the automatic
# rollback that is the entire reason for having two slots simply did not exist.
# ab-mark-good instead failed on every boot, leaving the machine permanently
# `degraded`, which the agent reports upstream, which stalls health-gated
# rollouts. Both blamed a read-only /boot in their error messages.
#
# Resolved at runtime rather than at build time so that one file is correct
# everywhere, including on a machine whose family nobody recorded.

# ab_grubenv_init sets GRUBENV and GRUB_EDITENV, or returns 1 having said why.
ab_grubenv_init() {
    GRUB_EDITENV=""
    for _c in grub-editenv grub2-editenv; do
        if command -v "$_c" >/dev/null 2>&1; then GRUB_EDITENV="$_c"; break; fi
    done
    if [ -z "$GRUB_EDITENV" ]; then
        echo "neither grub-editenv nor grub2-editenv is installed; cannot read or" >&2
        echo "write the boot environment, so slot state cannot be recorded." >&2
        return 1
    fi

    # The directory GRUB actually reads is the one its core image was built with
    # a prefix for, so prefer an env block that already exists over guessing.
    GRUBENV=""
    for _e in /boot/grub2/grubenv /boot/grub/grubenv; do
        if [ -f "$_e" ]; then GRUBENV="$_e"; break; fi
    done
    if [ -z "$GRUBENV" ]; then
        echo "no grubenv found at /boot/grub2/grubenv or /boot/grub/grubenv." >&2
        echo "This machine's boot environment is missing, not merely unwritable:" >&2
        echo "slot order and probation cannot be recorded, so an update could not" >&2
        echo "be rolled back automatically." >&2
        return 1
    fi
    return 0
}
