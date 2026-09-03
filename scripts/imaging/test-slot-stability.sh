#!/bin/bash
# A machine that boots successfully must keep booting the same slot.
#
# grub.cfg arms a one-shot fallback every time it picks a slot: it sets
# <SLOT>_TRY=1 and saves it before handing over to the kernel. ab-mark-good.sh
# resets that counter once the system is up. If the reset does not happen the
# next boot silently lands on the *other* slot -- which is the fallback working
# exactly as designed, and indistinguishable from the machine deciding to
# reinstall itself as far as anyone watching is concerned.
#
# Nothing tested this. test-update-bundle.sh greps for the string ab-mark-good
# in one boot's console and warns if it is missing; no test has ever rebooted a
# healthy machine twice and asserted it came back to the slot it was on. So a
# machine that boots A, then B, then A, then B for the rest of its life would
# have shipped green.
#
#   docker run --rm --privileged -v "$PWD/output":/output -v "$PWD/scripts":/s \
#     -e SRC=/output/marktest.img -e ARCH=arm64 \
#     ubuntu:24.04 bash /s/test-slot-stability.sh
#
# Reads grubenv from outside the guest between boots rather than parsing the
# console: the counter is the thing under test, and the file is the truth.
set -u
export DEBIAN_FRONTEND=noninteractive

ARCH="${ARCH:-amd64}"
case "$ARCH" in
    amd64) QEMU_PKG=qemu-system-x86;  FW_PKG=ovmf;;
    arm64) QEMU_PKG=qemu-system-arm;  FW_PKG=qemu-efi-aarch64;;
    *) echo "HARNESS-FAIL: ARCH must be amd64 or arm64"; exit 1;;
esac
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq "$QEMU_PKG" "$FW_PKG" gdisk util-linux e2fsprogs grub-common \
    cryptsetup-bin >/dev/null 2>&1

# poweroff        -- boot, let it settle, power off. The control.
# hostname-reboot -- the reported recipe: boot once, `hostnamectl set-hostname`,
#                    then `reboot`. If only this one loses the slot, the
#                    hostname change is the trigger rather than the timing.
# early-reboot    -- what a person actually does: log in as soon as the prompt
#                    appears, change the hostname, reboot. ab-mark-good is
#                    ordered After=multi-user.target and does not run until well
#                    after login is possible, so this window is real and wide.
MODE="${MODE:-poweroff}"
# rollback        -- the other half of the contract. Arming the counter only
#                    for updates must not quietly disable the fallback, so this
#                    stages what an update stages (slot B unproven, ORDER=B A),
#                    makes B unhealthy, and asserts the machine falls back to A.
# health-fail     -- a health check that fails must stop the slot being
#                    blessed, so an update that boots but is not healthy still
#                    rolls back. Same staging as rollback, but the slot is left
#                    entirely functional and only the check says no.
# assigned-name   -- the imager leaves the name assigned in the web UI on the
#                    BOOT partition; machine-identity must apply it, and it must
#                    survive a reboot rather than reverting to the image's.
case "$MODE" in poweroff|hostname-reboot|early-reboot|rollback|health-fail|assigned-name) ;; *) echo "HARNESS-FAIL: bad MODE"; exit 1;; esac

SRC="${SRC:-/output/marktest.img}"
DISK="${DISK:-/output/slot-stability-${MODE}.img}"
SIZE="${SIZE:-16G}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-900}"
LOG="/output/slot-stability-${MODE}.log"

PASS=0; FAIL=0
ok()   { echo "    ok    $*"; PASS=$((PASS+1)); }
bad()  { echo "    FAIL  $*"; FAIL=$((FAIL+1)); }
fail() { echo "HARNESS-FAIL: $*"; exit 1; }

[ -f "$SRC" ] || fail "no $SRC"

rm -f "$DISK"; truncate -s "$SIZE" "$DISK"
dd if="$SRC" of="$DISK" bs=4M conv=notrunc status=none || fail "dd"
# Scratch only, and this test runs five times with five differently-named
# disks; leaving them behind was the biggest single contributor to filling
# the CI runner mid-suite (2026-08-16). Logs carry the evidence.
trap 'rm -f "$DISK"' EXIT

# What the imager does after writing: relocate the GPT backup header and grow
# the overlay partition into the rest of the disk. Without this the guest's
# first-boot-expand has more to do, which is exactly the slow first boot this
# test is about -- so do it the way a real deployment does.
sgdisk -e "$DISK" >/dev/null 2>&1
NUM=$(sgdisk -p "$DISK" 2>/dev/null | awk '$NF == "overlay" { print $1; exit }')
[ -n "$NUM" ] || fail "no overlay partition"
START=$(sgdisk -i "$NUM" "$DISK" 2>/dev/null | awk '/First sector/ { print $3; exit }')
TYPEG=$(sgdisk -i "$NUM" "$DISK" 2>/dev/null | awk '/Partition GUID code/ { print $4; exit }')
UNIQG=$(sgdisk -i "$NUM" "$DISK" 2>/dev/null | awk '/Partition unique GUID/ { print $4; exit }')
sgdisk -d "$NUM" -n "${NUM}:${START}:0" -t "${NUM}:${TYPEG}" -u "${NUM}:${UNIQG}" \
       -c "${NUM}:overlay" "$DISK" >/dev/null 2>&1 || fail "grow"

# --- attach, and find the partitions by label rather than by number ----------
attach() {
    LO=$(losetup -f --show -P "$DISK") || fail "losetup"
    BB=$(basename "$LO")
    for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
        IFS=: read -r mj mn < "/sys/class/block/${BB}p$n/dev"
        rm -f "/dev/${BB}p$n"; mknod "/dev/${BB}p$n" b "$mj" "$mn"
    done
    BOOTP=""
    for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
        [ "$(blkid -o value -s LABEL "/dev/${BB}p$n" 2>/dev/null)" = BOOT ] && \
            { BOOTP="/dev/${BB}p$n"; break; }
    done
    [ -n "$BOOTP" ] || fail "no partition labelled BOOT"
}
detach() {
    local m
    for m in $MAPPED; do cryptsetup close "$m" 2>/dev/null; done
    MAPPED=""
    losetup -d "$LO" 2>/dev/null
}

# Encrypted images keep the slot and overlay filesystems inside LUKS
# containers, so the labels the loops below match on are invisible until the
# containers are opened -- an unopened image reads as "no slots at all" and the
# probe is silently installed nowhere. The key is taken the way the machine
# itself gets it: the keyfile the builder leaves on the plaintext BOOT
# partition (--unlock keyfile), falling back to the build passphrase in $PASS.
# Unencrypted images have no LUKS containers and both loops are no-ops.
PASS="${PASS:-testluks}"                 # --luks-passphrase used at build time
MAPPED=""
open_luks() {
    local n dev name i=0 key=""
    mkdir -p /mnt/bootk
    if mount -o ro "$BOOTP" /mnt/bootk 2>/dev/null; then
        if [ -f /mnt/bootk/ab-keys/luks.key ]; then
            cp /mnt/bootk/ab-keys/luks.key /tmp/slot-luks.key
            key=/tmp/slot-luks.key
        fi
        umount /mnt/bootk
    fi
    for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
        dev="/dev/${BB}p$n"
        cryptsetup isLuks "$dev" 2>/dev/null || continue
        i=$((i+1)); name="slotcheck-$i"
        if [ -n "$key" ] && cryptsetup open --key-file "$key" "$dev" "$name" 2>/dev/null; then
            :
        elif printf '%s' "$PASS" | cryptsetup open "$dev" "$name" - 2>/dev/null; then
            :
        else
            fail "cannot open LUKS container $dev (tried the BOOT keyfile and \$PASS)"
        fi
        MAPPED="$MAPPED $name"
    done
}

devs() {   # every filesystem-bearing device: plain partitions, then opened LUKS
    local n m
    for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
        cryptsetup isLuks "/dev/${BB}p$n" 2>/dev/null && continue
        echo "/dev/${BB}p$n"
    done
    for m in $MAPPED; do echo "/dev/mapper/$m"; done
}

grubenv_get() {                # grubenv_get <VAR>
    attach
    mkdir -p /mnt/bootp; mount "$BOOTP" /mnt/bootp || fail "mount BOOT"
    local v
    v=$(grub-editenv /mnt/bootp/grub/grubenv list 2>/dev/null | sed -n "s/^$1=//p")
    umount /mnt/bootp; detach
    echo "$v"
}

grubenv_dump() {
    attach
    mkdir -p /mnt/bootp; mount "$BOOTP" /mnt/bootp || fail "mount BOOT"
    grub-editenv /mnt/bootp/grub/grubenv list 2>/dev/null | sed 's/^/      /'
    umount /mnt/bootp; detach
}

# --- a probe that reports the slot and powers off ----------------------------
#
# Ordered After=ab-mark-good.service, so the guest is only shut down once the
# unit that resets the counter has had its turn. A probe that raced it would
# make this test measure its own timing rather than the machine's.
install_probe() {
    attach
    open_luks
    local slots="" d
    mkdir -p /mnt/slot
    for d in $(devs); do
        mount "$d" /mnt/slot 2>/dev/null || continue
        if [ -d /mnt/slot/usr/local/sbin ] && [ -d /mnt/slot/etc/systemd/system ]; then
            slots="$slots ${d##*/}"
            cat > /mnt/slot/usr/local/sbin/ab-slot-probe.sh <<PROBE
#!/bin/sh
exec > /dev/console 2>&1
MODE="$MODE"
PROBE
            cat >> /mnt/slot/usr/local/sbin/ab-slot-probe.sh <<'PROBE'
# The stage counter lives on the overlay partition, which both slots share, so
# the first boot is the first boot regardless of which slot serves it.
STAGE_FILE=/var/lib/overlay/.probe-stage
STAGE=$(cat "$STAGE_FILE" 2>/dev/null || echo 0)
STAGE=$((STAGE + 1))
echo "$STAGE" > "$STAGE_FILE" 2>/dev/null
sync

# Written to the overlay partition as well as the console. The console is
# shared with a getty, which mangles and swallows output -- the first run of
# this harness powered the guest off correctly and reported nothing at all.
# A file on the shared partition is read from outside, between boots.
REPORT=/var/lib/overlay/probe-$STAGE.txt
{
echo "stage=$STAGE slot=$(sed -n 's/.*rauc.slot=\([AB]\).*/\1/p' /proc/cmdline)"
echo "mark-good-status=$(systemctl is-active ab-mark-good.service 2>/dev/null)"
echo "mark-good-result=$(systemctl show -p Result --value ab-mark-good.service 2>/dev/null)"
echo "health-check=$(systemctl is-active ab-health-check.service 2>/dev/null)"
echo "boot-complete=$(systemctl is-active boot-complete.target 2>/dev/null)"
echo "grubenv=$(grub-editenv /boot/grub/grubenv list 2>&1 | tr '\n' ' ')"
echo "boot-mounted=$(findmnt -no SOURCE /boot 2>/dev/null || echo NONE)"
echo "boot-rw=$(findmnt -no OPTIONS /boot 2>/dev/null | cut -d, -f1)"
echo "hostname=$(hostname)"
# The cycle-breaking decision, in systemd's own words. Which job it deleted is
# the whole question: ab-checkin is harmless, ab-mark-good is the bug.
journalctl -b --no-pager 2>/dev/null | grep -i "ordering cycle\|deleted to break" | sed 's/^/cycle: /'
journalctl -b -u ab-mark-good --no-pager 2>/dev/null | tail -6 | sed 's/^/log: /'
} > "$REPORT" 2>&1
sync
sed 's/^/AB-SLOT-PROBE /' "$REPORT"
echo "AB-SLOT-PROBE-END"

# The reported recipe, exactly: change the hostname on the first boot and
# reboot -- not power off. `reboot` and `poweroff` run the same shutdown
# transaction, so if only one of them loses the try counter the difference is
# the hostname change, not the reset.
if { [ "$MODE" = hostname-reboot ] || [ "$MODE" = early-reboot ]; } && [ "$STAGE" = 1 ]; then
    echo "AB-SLOT-PROBE action=hostnamectl+reboot"
    hostnamectl set-hostname repro-renamed 2>&1 | sed 's/^/AB-SLOT-PROBE hostnamectl: /'
    sync
    systemctl reboot --no-block
    exit 0
fi
systemctl poweroff --no-block
PROBE
            chmod 0755 /mnt/slot/usr/local/sbin/ab-slot-probe.sh
            # Deliberately NOT After=/Wants=ab-mark-good.service. That is the
            # unit under test, and it sits in an ordering cycle with
            # multi-user.target -- adding another edge to that cycle would
            # change which job systemd deletes to break it, so the probe would
            # be measuring itself. Ordered only after multi-user.target, the
            # same as ab-mark-good, and it waits rather than depends.
            if [ "$MODE" = early-reboot ]; then
                # Stand in for a person: usable system, prompt on the console,
                # reboot before ab-mark-good's turn comes round. Ordered after
                # basic.target rather than multi-user.target precisely because
                # that is the gap under test -- ab-mark-good waits for the
                # target, a logged-in human does not.
                cat > /mnt/slot/etc/systemd/system/ab-slot-probe.service <<'UNIT'
[Unit]
Description=Stand in for an operator who logs in and reboots promptly
After=basic.target
[Service]
Type=oneshot
ExecStartPre=/bin/sleep 45
ExecStart=/usr/local/sbin/ab-slot-probe.sh
[Install]
WantedBy=basic.target
UNIT
                mkdir -p /mnt/slot/etc/systemd/system/basic.target.wants
                ln -sf /etc/systemd/system/ab-slot-probe.service \
                   /mnt/slot/etc/systemd/system/basic.target.wants/ab-slot-probe.service
            else
                cat > /mnt/slot/etc/systemd/system/ab-slot-probe.service <<'UNIT'
[Unit]
Description=Report the booted slot and the try counter, then power off
After=multi-user.target
[Service]
Type=oneshot
ExecStartPre=/bin/sleep 20
ExecStart=/usr/local/sbin/ab-slot-probe.sh
[Install]
WantedBy=multi-user.target
UNIT
            fi
            mkdir -p /mnt/slot/etc/systemd/system/multi-user.target.wants
            ln -sf /etc/systemd/system/ab-slot-probe.service \
               /mnt/slot/etc/systemd/system/multi-user.target.wants/ab-slot-probe.service
            sync
        fi
        umount /mnt/slot
    done
    detach
    echo "  probe installed in slot partition(s):$slots"
    # An empty list means every boot below runs probeless to its timeout and
    # the failure reads as "the probe never ran" -- fail here, where the cause
    # is, not three ten-minute boots later.
    [ -n "$slots" ] || fail "no slot filesystem found to install the probe into"
}

boot() {                       # boot <label>
    echo ""
    echo "=== boot: $1 (up to ${BOOT_TIMEOUT}s) ==="
    : > "$LOG"
    if [ "$ARCH" = arm64 ]; then
        # A writable copy of the firmware vars, and the code image padded to the
        # 64 MiB the machine model expects.
        [ -f /tmp/AAVMF_CODE.fd ] || {
            cp /usr/share/AAVMF/AAVMF_CODE.fd /tmp/AAVMF_CODE.fd 2>/dev/null || \
            cp /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /tmp/AAVMF_CODE.fd
            truncate -s 64m /tmp/AAVMF_CODE.fd
        }
        rm -f /tmp/AAVMF_VARS.fd; truncate -s 64m /tmp/AAVMF_VARS.fd
        timeout "$BOOT_TIMEOUT" qemu-system-aarch64 -M virt -cpu max -m 2048 -smp 2 \
            -drive if=pflash,format=raw,readonly=on,file=/tmp/AAVMF_CODE.fd \
            -drive if=pflash,format=raw,file=/tmp/AAVMF_VARS.fd \
            -drive file="$DISK",format=raw,if=virtio \
            -nographic -serial mon:stdio -no-reboot >> "$LOG" 2>&1
    else
        timeout "$BOOT_TIMEOUT" qemu-system-x86_64 -m 2048 -smp 2 \
            -drive file="$DISK",format=raw,if=virtio \
            -nographic -serial mon:stdio -no-reboot >> "$LOG" 2>&1
    fi
    grep -a "AB-SLOT-PROBE" "$LOG" | sed 's/^/  /' | tail -20
}

# The console is shared with a getty, which mangles and can swallow the probe's
# output entirely -- the first two runs of this harness reported "the probe
# never ran" on boots where it demonstrably had. The report file on the shared
# overlay partition is the reliable source; the console is only a convenience.
probe_slot() {                 # probe_slot <stage>
    attach
    open_luks
    mkdir -p /mnt/o
    local v="" d
    for d in $(devs); do
        [ "$(blkid -o value -s LABEL "$d" 2>/dev/null)" = overlay ] || continue
        mount "$d" /mnt/o 2>/dev/null || break
        v=$(sed -n 's/^stage=[0-9]* slot=//p' "/mnt/o/probe-$1.txt" 2>/dev/null | tr -d "\r")
        umount /mnt/o
        break
    done
    detach
    echo "$v"
}

probe_report() {               # probe_report <stage>
    attach
    open_luks
    mkdir -p /mnt/o
    local d
    for d in $(devs); do
        [ "$(blkid -o value -s LABEL "$d" 2>/dev/null)" = overlay ] || continue
        mount "$d" /mnt/o 2>/dev/null || break
        sed 's/^/      /' "/mnt/o/probe-$1.txt" 2>/dev/null
        umount /mnt/o
        break
    done
    detach
}

# --- stage an update that boots but is not healthy ---------------------------
#
# Exactly what ab-slot-pending.sh does after RAUC writes a slot: the target is
# unproven and first in ORDER. Then ab-mark-good is masked in slot B alone, so B
# boots and never clears its probation -- which is what a bad update looks like
# from the bootloader's side. If the fallback still works, boot 2 is back on A.
prime_rollback() {
    attach
    mkdir -p /mnt/bootp /mnt/slot
    mount "$BOOTP" /mnt/bootp || fail "mount BOOT"
    grub-editenv /mnt/bootp/grub/grubenv set ORDER="B A" B_PROVEN=0 B_TRY=0 \
        || fail "could not stage the pending slot"
    echo "  staged: ORDER=B A, B_PROVEN=0 (what ab-slot-pending.sh writes)"
    umount /mnt/bootp
    open_luks
    local d staged=""
    for d in $(devs); do
        [ "$(blkid -o value -s LABEL "$d" 2>/dev/null)" = rootfs-b ] || continue
        staged=1
        mount "$d" /mnt/slot || fail "mount rootfs-b"
        if [ "$MODE" = health-fail ]; then
            # Nothing masked and nothing broken: the slot boots perfectly and a
            # health check says it is not fit to keep. That is the only thing
            # standing between this update and being blessed.
            mkdir -p /mnt/slot/etc/ab/health.d
            printf '#!/bin/sh\necho "the application is not serving"\nexit 1\n' \
                > /mnt/slot/etc/ab/health.d/99-fails.sh
            chmod 0755 /mnt/slot/etc/ab/health.d/99-fails.sh
            echo "  slot B: a failing health check installed; nothing else changed"
        else
            # Masked, not deleted: systemd reports it as masked in the probe
            # report, so a run that failed for some other reason is
            # distinguishable.
            ln -sf /dev/null /mnt/slot/etc/systemd/system/ab-mark-good.service
            echo "  slot B: ab-mark-good masked, so probation is never cleared"
        fi
        sync; umount /mnt/slot
        break
    done
    detach
    # A rollback test whose staging silently did nothing would "pass" by
    # watching a healthy machine boot slot B twice.
    [ -n "$staged" ] || fail "no filesystem labelled rootfs-b to stage the rollback in"
}

# What imager/init writes to the BOOT partition after dd'ing the image, for a
# machine the web UI has given a name. No checkin_url on purpose: ab-checkin
# exits immediately without one, so this does not spend the boot waiting on a
# provisioning server that is not there.
ASSIGNED=assigned-01
prime_assigned_name() {
    attach
    mkdir -p /mnt/bootp
    mount "$BOOTP" /mnt/bootp || fail "mount BOOT"
    printf '{"image":"test","id":"aa:bb:cc:dd:ee:01","hostname":"%s"}\n' "$ASSIGNED" \
        > /mnt/bootp/ab-deploy.json
    sync; umount /mnt/bootp; detach
    echo "  wrote /boot/ab-deploy.json with hostname=$ASSIGNED"
}

install_probe
case "$MODE" in rollback|health-fail) prime_rollback;; esac
[ "$MODE" = assigned-name ] && prime_assigned_name

echo ""
echo "=== grubenv as imaged ==="
grubenv_dump
[ "$(grubenv_get A_TRY)" = "0" ] && ok "A_TRY starts at 0" \
                                 || bad "A_TRY is $(grubenv_get A_TRY) before any boot"

# --- boot 1: the slow one, straight after imaging ----------------------------
boot "first boot after imaging"
S1=$(probe_slot 1)
[ -n "$S1" ] || fail "the probe never ran on boot 1 (see $LOG)"
ok "boot 1 came up on slot $S1"
echo "  --- boot 1 report ---"; probe_report 1
if [ "$MODE" = rollback ] || [ "$MODE" = health-fail ]; then
    [ "$S1" = "B" ] && ok "boot 1 used the pending slot B, as ORDER says" \
                    || bad "boot 1 used slot $S1, expected the pending slot B"
else
    [ "$S1" = "A" ] && ok "boot 1 used slot A, as ORDER says" \
                    || bad "boot 1 used slot $S1, expected A"
fi

if [ "$MODE" = assigned-name ]; then
    H1=$(probe_report 1 | sed -n 's/^ *hostname=//p' | tr -d "\r")
    [ "$H1" = "$ASSIGNED" ] \
        && ok "boot 1 came up as '$ASSIGNED', not the image's own name" \
        || bad "boot 1 hostname is '$H1', expected '$ASSIGNED'"
fi

echo ""
echo "=== grubenv after boot 1 ==="
grubenv_dump
T1=$(grubenv_get "${S1}_TRY")
if [ "$MODE" = rollback ] || [ "$MODE" = health-fail ]; then
    # The probation was armed and spent. If grub.cfg had not armed it, the
    # counter would still be 0 and the unhealthy slot would boot forever.
    [ "$T1" = "1" ] && ok "${S1}_TRY=1: the pending slot was put on probation" \
                    || bad "${S1}_TRY is '$T1'; the pending slot was never put on probation, so there is no fallback"
elif [ "$T1" = "0" ]; then
    ok "${S1}_TRY is 0 after a healthy boot"
    [ "$(grubenv_get "${S1}_PROVEN")" = "1" ] \
        && ok "${S1}_PROVEN=1, so later boots are not put on probation" \
        || bad "${S1}_PROVEN is '$(grubenv_get "${S1}_PROVEN")'; every boot stays on probation"
else
    bad "${S1}_TRY is '$T1' after a healthy boot -- the next boot will fall through to the other slot"
fi

# --- boot 2: nothing changed, so nothing should move -------------------------
boot "second boot, unchanged machine"
S2=$(probe_slot 2)
[ -n "$S2" ] || fail "the probe never ran on boot 2 (see $LOG)"
if [ "$MODE" = rollback ] || [ "$MODE" = health-fail ]; then
    # The whole point of the fallback, and the thing arming-only-for-updates
    # must not break: an unhealthy update gets exactly one attempt.
    [ "$S2" = "A" ] && ok "boot 2 rolled back to slot A after the pending slot failed to mark good" \
                    || bad "boot 2 stayed on slot $S2; the automatic fallback did NOT happen"
elif [ "$S2" = "$S1" ]; then
    ok "boot 2 stayed on slot $S2"
else
    bad "boot 2 switched to slot $S2 with no update installed -- a healthy machine changed slots on its own"
fi

if [ "$MODE" = assigned-name ]; then
    # The name is stored on the overlay partition, not just written to
    # /etc/hostname, so it survives updates and is right in both slots. Boot 2
    # is where a name that was only ever set in memory would revert.
    H2=$(probe_report 2 | sed -n 's/^ *hostname=//p' | tr -d "\r")
    [ "$H2" = "$ASSIGNED" ] && ok "boot 2 is still '$ASSIGNED'" \
                           || bad "boot 2 hostname is '$H2'; the name did not persist"
fi

echo ""
echo "=== grubenv after boot 2 ==="
grubenv_dump

# --- boot 3: a switch that only shows up on the third boot is still a bug ----
boot "third boot"
S3=$(probe_slot 3)
[ -n "$S3" ] || fail "the probe never ran on boot 3 (see $LOG)"
# Compared against boot 2, not boot 1. A machine whose counter is never reset
# alternates -- A, B, A, B -- so "boot 3 is back on slot A" is not the machine
# holding still, it is the second half of the ping-pong, and comparing to boot 1
# reports it as a pass. Three boots rather than two exist precisely to show that
# shape; the failing run reads "slots booted: A -> B -> A".
if [ "$S3" = "$S2" ]; then
    ok "boot 3 stayed on slot $S3"
else
    bad "boot 3 switched to slot $S3 (boots went $S1 -> $S2 -> $S3, which alternates)"
fi

echo ""
echo "  slots booted: $S1 -> $S2 -> $S3"
echo "  passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
