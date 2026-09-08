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
# The live interface must end up configured. Matched on the lease line rather
# than a phrase like "Network up", which is wording and will change again.
grep -qE "eth1: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/" <<<"$OUT" \
    || fail "the imager never got a lease on the live interface"
grep -q "Target disk:" <<<"$OUT" \
    || fail "the imager never got past networking to disk selection"
# The point is not just that it recovers, but that it says so: a silent 16s gap
# per interface is what made this look like a hang rather than a wait.
grep -q "asking eth0 for a lease" <<<"$OUT" \
    || fail "the imager does not name the interface it is trying"

echo "[test] booting with TWO live DHCP networks — only one faces the server"
OUT2="$(docker run --rm -v "$IM":/im:ro --entrypoint sh alpine:3.20 -c '
    apk add -q qemu-system-x86_64 >/dev/null 2>&1
    truncate -s 4G /tmp/d.img
    # eth0 is an office LAN: it serves DHCP perfectly well and cannot reach the
    # provisioning server. Taking its lease and stopping is what put a machine on
    # the wrong network, reporting under the wrong MAC.
    timeout 180 qemu-system-x86_64 -m 1024 -smp 2 -nographic -no-reboot \
      -kernel /im/vmlinuz -initrd /im/initramfs.img \
      -append "imager.url=http://192.168.50.1/none.img imager.action=shell console=ttyS0,115200" \
      -netdev user,id=office,net=10.9.9.0/24,host=10.9.9.1 -device virtio-net-pci,netdev=office \
      -netdev user,id=prov,net=192.168.50.0/24,host=192.168.50.1 -device virtio-net-pci,netdev=prov \
      -drive file=/tmp/d.img,format=raw,if=virtio 2>&1
  ' | grep -aE "imager\]" || true)"

echo "$OUT2" | sed 's/^/    /'
echo

grep -q "eth0: 10.9.9" <<<"$OUT2" \
    || fail "the office interface did not get its lease; the test is not exercising the case"
grep -q "Using eth1 to reach 192.168.50.1" <<<"$OUT2" \
    || fail "the imager did not choose the interface facing the provisioning server.
    Taking the first lease puts the machine on the office LAN, unable to reach the
    server, reporting under the MAC of the wrong port — so the image assigned to
    the port that PXE-booted never matches."

echo -e "\033[0;32m[test] PASS:\033[0m gave up on the dead NIC, and chose the server-facing NIC over a live decoy"
