#!/bin/bash
# End-to-end imager test (runs inside a privileged qemu container):
#   1. serve /output over HTTP
#   2. boot the imager in QEMU; it fetches the image and writes it to a blank disk
#   3. boot the freshly imaged disk and confirm it reaches a login prompt
#
# IMAGE_FILE selects the image in /output (default: debian-trixie-ab.img).
set -u
IMAGE_FILE="${IMAGE_FILE:-debian-trixie-ab.img}"
# A name the image cannot possibly be carrying, so seeing it on the imaged disk
# proves it came from the kernel command line and nowhere else. This hop --
# iPXE argument to imager to /boot/ab-deploy.json -- was the one link in the
# chain nothing covered, and it is the link that broke: the parameter was
# added to the generated iPXE scripts and to the code that consumes the marker,
# while the imager in output/ was still an older build that ignored it. An
# imager that does not understand a parameter drops it silently, exactly as it
# should, so the machine images perfectly with the wrong name.
ASSIGNED_HOSTNAME="${ASSIGNED_HOSTNAME:-e2e-assigned}"
COMPRESS_MODE="${COMPRESS_MODE:-auto}"
FAILED=0
# amd64 by default, which is what CI runs natively. arm64 exists so this can be
# run on an Apple-silicon host without emulation -- the hop under test is
# architecture-independent, and a test nobody can run locally is a test that
# only ever runs after a mistake has shipped.
ARCH="${ARCH:-amd64}"
case "$ARCH" in
    # The console differs, and getting it wrong is silent: the kernel writes to
    # a device that does not exist, the imager's own output goes with it, and
    # the run looks like a hang rather than a misconfiguration.
    amd64) QEMU=qemu-system-x86_64; QEMU_PKG=qemu-system-x86; FW_PKG=ovmf
           IMGDIR=imager; CONSOLE=ttyS0;;
    arm64) QEMU=qemu-system-aarch64; QEMU_PKG=qemu-system-arm; FW_PKG=qemu-efi-aarch64
           IMGDIR=imager/arm64; CONSOLE=ttyAMA0;;
    *) echo "ARCH must be amd64 or arm64"; exit 1;;
esac
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq "$QEMU_PKG" "$FW_PKG" python3 >/dev/null 2>&1

qemu_args() {   # machine-specific flags; -kernel/-initrd work on both
    if [ "$ARCH" = arm64 ]; then
        [ -f /tmp/AAVMF_CODE.fd ] || {
            cp /usr/share/AAVMF/AAVMF_CODE.fd /tmp/AAVMF_CODE.fd 2>/dev/null || \
            cp /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /tmp/AAVMF_CODE.fd
            truncate -s 64m /tmp/AAVMF_CODE.fd
        }
        echo "-M virt -cpu max"
    else
        echo ""
    fi
}

cd /output
echo "=== serving /output on :8000 ==="
python3 -m http.server 8000 --bind 127.0.0.1 >/tmp/http.log 2>&1 &
sleep 2

echo "=== creating blank 8G target disk ==="
truncate -s 8G /output/target.img

echo "=== STAGE 1: netboot imager images the blank disk ==="
# shellcheck disable=SC2046
timeout 900 "$QEMU" $(qemu_args) -m 1536 -smp 2 \
  -kernel "/output/${IMGDIR}/vmlinuz" \
  -initrd "/output/${IMGDIR}/initramfs.img" \
  -append "imager.url=http://10.0.2.2:8000/${IMAGE_FILE} imager.compress=${COMPRESS_MODE} imager.action=poweroff imager.hostname=${ASSIGNED_HOSTNAME} console=${CONSOLE},115200" \
  -drive file=/output/target.img,format=raw,if=virtio \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -nographic -serial mon:stdio -no-reboot 2>&1 | tee /output/imager-e2e.log | grep -aiE "imager|network|target|writing|success|reboot|error|fatal"

echo ""
echo "=== imaged disk partition table ==="
apt-get install -y -qq gdisk >/dev/null 2>&1
sgdisk -p /output/target.img 2>&1 | tail -8

echo ""
echo "=== the imager recorded the assigned name for the installed system ==="
apt-get install -y -qq util-linux e2fsprogs >/dev/null 2>&1
LO=$(losetup -f --show -P /output/target.img)
BB=$(basename "$LO")
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    IFS=: read -r mj mn < "/sys/class/block/${BB}p$n/dev"
    rm -f "/dev/${BB}p$n"; mknod "/dev/${BB}p$n" b "$mj" "$mn"
done
mkdir -p /mnt/e2eboot
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    [ "$(blkid -o value -s LABEL "/dev/${BB}p$n" 2>/dev/null)" = BOOT ] || continue
    mount "/dev/${BB}p$n" /mnt/e2eboot 2>/dev/null || break
    if [ -r /mnt/e2eboot/ab-deploy.json ]; then
        echo "  ab-deploy.json: $(cat /mnt/e2eboot/ab-deploy.json)"
        # The id is how the web UI joins a machine's imaging progress to its
        # later check-in. It was computed before any network driver was loaded,
        # so no interface existed, and every machine fell back to "unknown-1" --
        # one row in the UI for the whole fleet.
        if grep -qE '"id"[[:space:]]*:[[:space:]]*"([0-9a-f]{2}:){5}[0-9a-f]{2}"' /mnt/e2eboot/ab-deploy.json; then
            echo "  ok   the machine identified itself by MAC address"
        else
            echo "  FAIL the machine did not identify itself by MAC"
            echo "       a fleet reporting one shared id collides into a single UI row"
            FAILED=1
        fi
        if grep -q "\"hostname\"[[:space:]]*:[[:space:]]*\"${ASSIGNED_HOSTNAME}\"" /mnt/e2eboot/ab-deploy.json; then
            echo "  ok   the assigned hostname reached the installed system"
        else
            echo "  FAIL the assigned hostname is not in ab-deploy.json"
            echo "       this imager does not understand imager.hostname -- rebuild it"
            FAILED=1
        fi
    else
        echo "  FAIL no ab-deploy.json on the BOOT partition"
        FAILED=1
    fi
    umount /mnt/e2eboot
    break
done
losetup -d "$LO" 2>/dev/null

echo ""
echo "=== STAGE 2: boot the freshly imaged disk ==="
[ "$ARCH" = arm64 ] && { rm -f /tmp/AAVMF_VARS.fd; truncate -s 64m /tmp/AAVMF_VARS.fd; }
# shellcheck disable=SC2046
timeout 360 "$QEMU" $(qemu_args) -m 1024 -smp 2 \
  $([ "$ARCH" = arm64 ] && echo "-drive if=pflash,format=raw,readonly=on,file=/tmp/AAVMF_CODE.fd -drive if=pflash,format=raw,file=/tmp/AAVMF_VARS.fd") \
  -drive file=/output/target.img,format=raw,if=virtio \
  -nographic -serial mon:stdio -no-reboot 2>&1 | tee /output/imaged-boot.log | grep -aiE "login:|Debian GNU|Reached target multi-user|Kernel panic|Cannot open root" | tail -5

# The login banner carries the hostname, so this is the assigned name arriving
# on a real running system rather than merely being recorded on a partition.
echo ""
if grep -qa "${ASSIGNED_HOSTNAME} login:" /output/imaged-boot.log; then
    echo "  ok   the machine booted as '${ASSIGNED_HOSTNAME}'"
else
    echo "  FAIL the machine did not boot as '${ASSIGNED_HOSTNAME}'"
    grep -ao "[a-z0-9-]* login:" /output/imaged-boot.log | tail -2 | sed 's/^/       saw: /'
    FAILED=1
fi

echo "=== done ==="
[ "$FAILED" -eq 0 ] || { echo "FAILED"; exit 1; }
echo "ALL PASS"
