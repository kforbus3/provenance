#!/usr/bin/env bash
# Can the imager boot a machine whose FIRST network interface faces nothing?
#
# It could not, and the reason was one missing flag. `udhcpc -q` quits AFTER a
# lease; the flag that makes it exit when there is no server is -n. Without it,
# udhcpc on a dead interface retried forever and the loop over interfaces never
# reached the live one. A correctly cabled machine sat on "Configuring network
# (DHCP)…" indefinitely while the provisioning server answered fine one port
# over.
#
# Every earlier test had a single NIC, or the live one first, so every earlier
# test passed. That is the whole reason this file exists: the bug is invisible
# unless the dead interface is enumerated first, which is the ordinary case on
# real hardware with several ports.
#
#   imager/test-multi-nic.sh output/imager
set -euo pipefail

IM="${1:-output/imager}"
[ -f "$IM/vmlinuz" ] && [ -f "$IM/initramfs.img" ] \
    || { echo "no imager at $IM (build it first)" >&2; exit 2; }
IM="$(cd "$IM" && pwd)"

echo "[test] booting the imager with a DEAD first NIC and a live second one"
OUT="$(docker run --rm -v "$IM":/im:ro --entrypoint sh alpine:3.20 -c '
    apk add -q qemu-system-x86_64 >/dev/null 2>&1
    truncate -s 4G /tmp/d.img
    # -netdev socket with nothing on the far end is a NIC with no DHCP server:
    # link present, nobody answering. That is the case that hung.
    timeout 180 qemu-system-x86_64 -m 1024 -smp 2 -nographic -no-reboot \
      -kernel /im/vmlinuz -initrd /im/initramfs.img \
      -append "imager.url=http://127.0.0.1/none.img imager.action=shell console=ttyS0,115200" \
      -netdev socket,id=dead,listen=127.0.0.1:19990 -device virtio-net-pci,netdev=dead \
      -netdev user,id=live -device virtio-net-pci,netdev=live \
      -drive file=/tmp/d.img,format=raw,if=virtio 2>&1
  ' | grep -aE "imager\]" || true)"

echo "$OUT" | sed 's/^/    /'
echo

fail() { echo -e "\033[0;31m[test] FAIL:\033[0m $*" >&2; exit 1; }

grep -q "no lease on eth0" <<<"$OUT" \
    || fail "the imager never gave up on the dead interface — is -n still on udhcpc?"
grep -q "Network up on eth1" <<<"$OUT" \
    || fail "the imager never reached the live interface"
# The point is not just that it recovers, but that it says so: a silent 16s gap
# per interface is what made this look like a hang rather than a wait.
grep -q "asking eth0 for a lease" <<<"$OUT" \
    || fail "the imager does not name the interface it is trying"

echo -e "\033[0;32m[test] PASS:\033[0m gave up on the dead NIC and imaged from the live one"
