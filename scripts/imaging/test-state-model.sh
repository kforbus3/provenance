#!/bin/bash
# Boot an image twice -- once per slot -- and check that its state manifest
# describes what the running machine actually has.
#
# The container harness (test-state-directives.sh) proves the engine applies a
# manifest correctly. It cannot prove the result is a system that boots: that a
# tmpfs over /var/tmp does not upset systemd, that a bind over /var/log survives
# the switch to root, that a read-only slot still reaches a login prompt. Those
# only show up in a real boot, which is what this is.
#
# The probe is generated from the image's own manifest rather than hardcoded, so
# this test covers whatever the image was built with -- the default overlay
# model, a handful of --persist paths, or a full --state-model stateful build.
#
#   docker run --rm --privileged --platform linux/arm64 \
#     -v "$PWD/output":/output -v "$PWD/scripts":/s \
#     -e SRC=/output/prim-test.img -e BOOT_TIMEOUT=1500 \
#     ubuntu:24.04 bash /s/test-state-model.sh
#
# BOOT_TIMEOUT matters: an x86 guest on an arm64 host has no KVM and runs under
# TCG, where a Debian boot takes several minutes rather than seconds.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq qemu-system-x86 gdisk util-linux e2fsprogs >/dev/null 2>&1

SRC="${SRC:-/output/prim-test.img}"
DISK="${DISK:-/output/state-model-target.img}"
SIZE="${SIZE:-32G}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-1500}"
LOG=/output/state-model-boot.log

PASS=0; FAIL=0
ok()  { echo "    ok    $*"; PASS=$((PASS+1)); }
bad() { echo "    FAIL  $*"; FAIL=$((FAIL+1)); }
fail(){ echo "HARNESS-FAIL: $*"; exit 1; }

[ -f "$SRC" ] || fail "no $SRC"

rm -f "$DISK"; truncate -s "$SIZE" "$DISK"
dd if="$SRC" of="$DISK" bs=4M conv=notrunc status=none || fail "dd"

# The imager's post-write steps: move the GPT backup header and grow the overlay
# partition into the rest of the disk.
sgdisk -e "$DISK" >/dev/null 2>&1
NUM=$(sgdisk -p "$DISK" 2>/dev/null | awk '$NF == "overlay" { print $1; exit }')
[ -n "$NUM" ] || fail "no overlay partition"
START=$(sgdisk -i "$NUM" "$DISK" 2>/dev/null | awk '/First sector/ { print $3; exit }')
TYPEG=$(sgdisk -i "$NUM" "$DISK" 2>/dev/null | awk '/Partition GUID code/ { print $4; exit }')
UNIQG=$(sgdisk -i "$NUM" "$DISK" 2>/dev/null | awk '/Partition unique GUID/ { print $4; exit }')
sgdisk -d "$NUM" -n "${NUM}:${START}:0" -t "${NUM}:${TYPEG}" -u "${NUM}:${UNIQG}" \
       -c "${NUM}:overlay" "$DISK" >/dev/null 2>&1 || fail "grow"

LO=$(losetup -f --show -P "$DISK") || fail "losetup"
BB=$(basename "$LO")
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    IFS=: read -r mj mn < "/sys/class/block/${BB}p$n/dev"
    rm -f "/dev/${BB}p$n"; mknod "/dev/${BB}p$n" b "$mj" "$mn"
done
cleanup() { umount /mnt/slot 2>/dev/null; umount /mnt/boot 2>/dev/null
            losetup -d "$LO" 2>/dev/null
            # Scratch only: the evidence a failure needs is the logs. Every
            # test in the suite leaving its ~8 GB disk behind filled the CI
            # runner and killed it mid-suite (2026-08-16).
            rm -f "$DISK"; }
trap cleanup EXIT

# --- read the manifest out of the image --------------------------------------
mkdir -p /mnt/slot /mnt/boot
SLOTS=""
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    mount "/dev/${BB}p$n" /mnt/slot 2>/dev/null || continue
    if [ -d /mnt/slot/usr/local/sbin ] && [ -d /mnt/slot/etc/systemd/system ]; then
        SLOTS="$SLOTS $n"
    fi
    umount /mnt/slot
done
set -- $SLOTS
[ $# -ge 2 ] || fail "expected two root slots, found: '$SLOTS'"
mount "/dev/${BB}p$1" /mnt/slot || fail "mount slot"
CONF=/mnt/slot/usr/lib/ab/state.conf
[ -r "$CONF" ] || fail "the image has no /usr/lib/ab/state.conf"
MODEL=$(awk '$1=="model"{print $2}' "$CONF")
# `upper per-slot` inverts what "shared" means for every overlay directive, so
# it has to be read here rather than assumed. Without it this harness reports a
# per-slot image's correct behaviour as data loss, which is precisely the mistake
# it already made once over appliance's reset-on-update /var.
UPPER_MODE=$(awk '$1=="upper"{print $2; exit}' "$CONF")
[ -n "$UPPER_MODE" ] || UPPER_MODE=shared
# What the machine stamps into /var/lib/overlay/.model. The upper mode is part of
# that identity because it decides which directory every write lands in.
MODEL_ID="$MODEL"
[ "$UPPER_MODE" = per-slot ] && MODEL_ID="$MODEL+per-slot-upper"
echo "=== manifest (model: ${MODEL:-none}, upper: $UPPER_MODE) ==="
grep -vE '^\s*(#|$)' "$CONF" | sed 's/^/  /'
MOUNTS=$(awk '$1=="overlay"||$1=="persist"||$1=="slot-private"||$1=="volatile"{print $1" "$2}' "$CONF")
# Is the root itself overlaid? If so the interesting question -- does a change
# made in one slot follow you into the other -- is about /, which the per-path
# probe below deliberately skips. It gets its own marker instead.
ROOT_OVERLAY=$(awk '$1=="overlay" && $2=="/"{print 1; exit}' "$CONF")
# reset-on-update changes what "shared between slots" means for a path. The
# appliance model persists /var and then resets it on every slot change, and a
# test that did not read this reported that correct behaviour as data loss.
RESETS=$(awk '$1=="reset-on-update"{print $2}' "$CONF")
umount /mnt/slot

is_reset() {                   # is_reset <path> -- does a reset directive cover it?
    for r in $RESETS; do
        case "$1" in "$r"|"$r"/*) return 0;; esac
    done
    return 1
}

# --- build the probe from the manifest ---------------------------------------
# Each directive gets one line of output naming the path, what the kernel says
# is mounted there, and whether a file written on the previous boot is visible.
# The second boot is a different slot, which is what makes "shared" and
# "slot-private" distinguishable at all.
{
    echo '#!/bin/sh'
    echo 'exec > /dev/console 2>&1'
    echo 'echo "AB-STATE-PROBE-START"'
    echo 'echo "slot: $(sed -n '"'"'s/.*rauc.slot=\([AB]\).*/\1/p'"'"' /proc/cmdline)"'
    echo 'echo "root-source: $(findmnt -no SOURCE / 2>/dev/null)"'
    echo 'echo "root-rw: $(findmnt -no OPTIONS / 2>/dev/null | cut -d, -f1)"'
    echo 'echo "model-recorded: $(cat /var/lib/overlay/.model 2>/dev/null)"'
    echo 'echo "upper-dirs: $(ls -d /var/lib/overlay/upper* 2>/dev/null | tr "\n" " ")"'
    # A file written into the root overlay on boot 1 and read back on boot 2,
    # which is the whole question `upper per-slot` answers: with a shared upper
    # the second slot sees slot A's mark, with a per-slot upper it sees nothing.
    # /etc rather than / itself -- a stray file in / would be odd on a machine
    # this test leaves behind for someone to poke at.
    if [ -n "$ROOT_OVERLAY" ]; then
        cat <<'ROOTPROBE'
echo "seen-root $([ -f /etc/.ab-probe-root ] && cat /etc/.ab-probe-root || echo none)"
echo "$(sed -n 's/.*rauc.slot=\([AB]\).*/\1/p' /proc/cmdline)" > /etc/.ab-probe-root 2>/dev/null \
  && echo "write-root ok" || echo "write-root FAILED"
ROOTPROBE
    fi
    printf '%s\n' "$MOUNTS" | while read -r verb mp; do
        [ -n "$mp" ] || continue
        [ "$mp" = "/" ] && continue
        cat <<PROBE
echo "path $mp verb=$verb fstype=\$(findmnt -no FSTYPE '$mp' 2>/dev/null) source=\$(findmnt -no SOURCE '$mp' 2>/dev/null)"
echo "seen $mp \$([ -f '$mp/.ab-probe-mark' ] && cat '$mp/.ab-probe-mark' || echo none)"
mkdir -p '$mp' 2>/dev/null
echo "\$(sed -n 's/.*rauc.slot=\([AB]\).*/\1/p' /proc/cmdline)" > '$mp/.ab-probe-mark' 2>/dev/null \\
  && echo "write $mp ok" || echo "write $mp FAILED"
PROBE
    done
    echo 'echo "AB-STATE-PROBE-END"'
    echo 'systemctl poweroff --no-block'
} > /tmp/probe.sh

echo ""
echo "=== probe ==="
sed 's/^/  /' /tmp/probe.sh | head -8
echo "  ..."

# Both slots get it: boot 2 runs the other one.
for n in $SLOTS; do
    mount "/dev/${BB}p$n" /mnt/slot || fail "mount slot $n"
    install -m 0755 /tmp/probe.sh /mnt/slot/usr/local/sbin/ab-state-probe.sh
    cat > /mnt/slot/etc/systemd/system/ab-state-probe.service <<'UNIT'
[Unit]
Description=Report the writable-state layout to the console, then power off
After=multi-user.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ab-state-probe.sh
[Install]
WantedBy=multi-user.target
UNIT
    mkdir -p /mnt/slot/etc/systemd/system/multi-user.target.wants
    ln -sf /etc/systemd/system/ab-state-probe.service \
       /mnt/slot/etc/systemd/system/multi-user.target.wants/ab-state-probe.service
    sync; umount /mnt/slot
done

# Drop `quiet` so the initramfs stage is visible in the log.
BOOTP=$(for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
            blkid -s TYPE -o value "/dev/${BB}p$n" 2>/dev/null | grep -q ext && \
              debugfs -R "ls /grub" "/dev/${BB}p$n" 2>/dev/null | grep -q grub.cfg && \
              { echo "$n"; break; }
        done)
[ -n "$BOOTP" ] && { mount "/dev/${BB}p$BOOTP" /mnt/boot && \
    sed -i 's/ quiet//g' /mnt/boot/grub/grub.cfg && umount /mnt/boot; }

# Boot the other slot second by putting it first in GRUB's ORDER.
set_order() {
    mount "/dev/${BB}p$BOOTP" /mnt/boot || return 1
    grub-editenv /mnt/boot/grub/grubenv set ORDER="$1" 2>/dev/null || \
        printf '# GRUB Environment Block\nORDER=%s\n' "$1" > /mnt/boot/grub/grubenv
    umount /mnt/boot
}

losetup -d "$LO"; trap 'rm -f "$DISK"' EXIT   # scratch disk only; logs carry the evidence

boot() {                       # boot <label>
    echo ""
    echo "=== boot: $1 (up to ${BOOT_TIMEOUT}s) ==="
    timeout "$BOOT_TIMEOUT" qemu-system-x86_64 -m 2048 -smp 2 \
        -drive file="$DISK",format=raw,if=virtio \
        -nographic -serial mon:stdio -no-reboot >> "$LOG" 2>&1
    sed -n '/AB-STATE-PROBE-START/,/AB-STATE-PROBE-END/p' "$LOG" | tail -60 | sed 's/^/  /'
}

: > "$LOG"
boot "first slot"
FIRST=$(sed -n '/AB-STATE-PROBE-START/,/AB-STATE-PROBE-END/p' "$LOG")
: > "$LOG"
LO=$(losetup -f --show -P "$DISK"); BB=$(basename "$LO")
for n in $(ls /sys/class/block/ | sed -n "s/^${BB}p//p" | sort -n); do
    IFS=: read -r mj mn < "/sys/class/block/${BB}p$n/dev"
    rm -f "/dev/${BB}p$n"; mknod "/dev/${BB}p$n" b "$mj" "$mn"
done
set_order "B A"
losetup -d "$LO"
boot "other slot"
SECOND=$(sed -n '/AB-STATE-PROBE-START/,/AB-STATE-PROBE-END/p' "$LOG")

# --- assertions ---------------------------------------------------------------
echo ""
echo "=== result ==="
[ -n "$FIRST" ]  || fail "the first boot's probe never ran"
[ -n "$SECOND" ] || fail "the second boot's probe never ran"

S1=$(printf '%s\n' "$FIRST"  | sed -n 's/^slot: //p' | tr -d '\r')
S2=$(printf '%s\n' "$SECOND" | sed -n 's/^slot: //p' | tr -d '\r')
[ "$S1" != "$S2" ] && ok "the two boots used different slots ($S1 then $S2)" \
                   || bad "both boots used slot $S1; the slot-change paths were not exercised"

case "$MODEL" in
    overlay)
        printf '%s\n' "$FIRST" | grep -q "root-source: ab-root" \
            && ok "root is an overlay" || bad "root is not an overlay";;
    stateful|appliance)
        printf '%s\n' "$FIRST" | grep -q "root-source: ab-root" \
            && bad "root is an overlay, but model $MODEL says it should not be" \
            || ok "root is the slot itself, as model $MODEL requires"
        printf '%s\n' "$FIRST" | grep -q "root-rw: ro" \
            && ok "root is mounted read-only" || bad "root is not read-only";;
esac
printf '%s\n' "$FIRST" | grep -q "model-recorded: $MODEL_ID" \
    && ok "the machine recorded layout '$MODEL_ID'" \
    || bad "the machine did not record layout '$MODEL_ID'"

# --- the root overlay across a slot change ------------------------------------
#
# The property the option exists for, asserted on a real boot rather than in the
# container harness: a file written while running one slot either does or does
# not exist when the other comes up, and which of those is correct is decided by
# one line in the manifest.
if [ -n "$ROOT_OVERLAY" ]; then
    printf '%s\n' "$FIRST" | grep -q "write-root ok" \
        && ok "the root overlay is writable" || bad "the root overlay is not writable"
    sawroot=$(printf '%s\n' "$SECOND" | sed -n 's/^seen-root //p' | tr -d '\r')
    if [ "$UPPER_MODE" = per-slot ]; then
        [ "$sawroot" = "none" ] \
            && ok "slot $S2 did not inherit slot $S1's root writes (per-slot upper)" \
            || bad "slot $S2 saw slot $S1's root write '$sawroot'; the uppers are not separate"
        printf '%s\n' "$SECOND" | grep -q "upper-dirs:.*upper-A" && \
        printf '%s\n' "$SECOND" | grep -q "upper-dirs:.*upper-B" \
            && ok "both per-slot upper layers exist on the partition" \
            || bad "the partition does not have an upper-A and an upper-B"
    else
        [ "$sawroot" = "$S1" ] \
            && ok "slot $S2 inherited slot $S1's root writes (shared upper)" \
            || bad "slot $S2 lost slot $S1's root write (saw '$sawroot')"
    fi
fi

printf '%s\n' "$MOUNTS" | while read -r verb mp; do
    [ -n "$mp" ] && [ "$mp" != "/" ] || continue
    printf '%s\n' "$FIRST" | grep -q "write $mp ok" \
        && echo "    ok    $mp is writable" || echo "    FAIL  $mp is not writable"
    saw=$(printf '%s\n' "$SECOND" | sed -n "s|^seen $mp ||p" | tr -d '\r')
    case "$verb" in
        persist|overlay)
            if is_reset "$mp"; then
                [ "$saw" = "none" ] \
                    && echo "    ok    $mp reverted to the image on the slot change (reset-on-update)" \
                    || echo "    FAIL  $mp is reset-on-update but kept $S1's data (saw '$saw')"
            elif [ "$verb" = overlay ] && [ "$UPPER_MODE" = per-slot ]; then
                # Not data loss: this image gives each slot its own upper, so an
                # overlaid path is private by construction. persist is unaffected
                # -- it is a bind outside the overlay -- which is exactly why it
                # is the recommended way to share something anyway.
                [ "$saw" = "none" ] \
                    && echo "    ok    $mp is private to each slot (per-slot upper)" \
                    || echo "    FAIL  $mp leaked slot $S1's data into $S2 (saw '$saw')"
            else
                [ "$saw" = "$S1" ] && echo "    ok    $mp carried $S1's data into $S2 (shared)" \
                                   || echo "    FAIL  $mp lost its data across the slot change (saw '$saw')"
            fi;;
        slot-private)
            [ "$saw" = "none" ] && echo "    ok    $mp is private to each slot" \
                                || echo "    FAIL  $mp leaked slot $S1's data into $S2 (saw '$saw')";;
        volatile)
            [ "$saw" = "none" ] && echo "    ok    $mp kept nothing across the reboot" \
                                || echo "    FAIL  $mp persisted across a reboot (saw '$saw')";;
    esac
done | tee /tmp/perpath
PASS=$((PASS + $(grep -c '    ok  ' /tmp/perpath)))
FAIL=$((FAIL + $(grep -c '    FAIL' /tmp/perpath)))

echo ""
echo "  passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
