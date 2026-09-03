#!/bin/sh
# Kernel postinst hook: say plainly that this kernel will not be booted.
#
# On an A/B image the kernel is part of the image. GRUB boots
# /boot/<A|B>/vmlinuz -- one pair per slot, replaced only by a RAUC bundle --
# while dpkg installs /boot/vmlinuz-<version>. Nothing connects the two, and
# that is deliberate: a kernel swapped in underneath a slot would no longer
# match the root filesystem it was built against, and a rollback to the other
# slot would be the only thing standing between you and an unbootable machine.
#
# So an apt-installed kernel is inert here. It occupies space on /boot and is
# never booted. The only supported way to change the kernel is to build a new
# image and ship it as a bundle (docs/UPDATES.md).
#
# This does not fail the apt transaction. A postinst that exits non-zero leaves
# dpkg half-configured and the machine needs hands to untangle it, which is a
# worse outcome than an ignored kernel -- but saying nothing at all would be
# worse still, because the machine would reboot on the old kernel with no
# indication why.
#
# $1 is the kernel version.
VERSION="${1:-the kernel just installed}"
SLOT="$(sed -n 's/.*rauc\.slot=\([AB]\).*/\1/p' /proc/cmdline 2>/dev/null)"

cat >&2 <<EOF

  ================================================================
  This is an A/B image: ${VERSION} will NOT be booted.

  GRUB boots /boot/${SLOT:-<slot>}/vmlinuz, which is part of the image and is
  replaced only by a RAUC update bundle. This machine will keep
  booting its current kernel after a reboot.

  To change the kernel: build a new image with it and install the
  bundle -- see docs/UPDATES.md, or run 'ab-update' if a newer
  bundle is already published.
  ================================================================

EOF
exit 0
