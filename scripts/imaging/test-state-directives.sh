#!/bin/bash
# Exercise the state-manifest engine directly, without booting anything.
#
# The initramfs script is the riskiest code in this project: it runs before
# there is a system to log into, its failures reach only the kernel log, and
# twice now a bug in it looked exactly like success from the outside. A QEMU
# boot proves the whole chain but takes minutes and tests one manifest per run,
# which is why bugs in it survived so long.
#
# This runs the real script -- not a copy, not a reimplementation -- against a
# fake root slot and a real loopback ext4 "overlay partition", with /proc/cmdline
# bind-mounted to whatever the case needs. Every directive combination is a case,
# and each one takes about a second.
#
#   docker run --rm --privileged --platform linux/amd64 \
#     -v "$PWD":/repo:ro ubuntu:24.04 bash /repo/scripts/imaging/test-state-directives.sh
#
# It does not replace the QEMU tests: it cannot prove the script is *in* the
# initramfs, that busybox has the tools it needs, or that systemd is happy with
# the result. Those are what test-overlay-boot.sh is for.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq e2fsprogs util-linux kmod >/dev/null 2>&1

# The shared script, at the path it lives at IN THIS REPO. It is installed to
# etc/initramfs-tools/scripts/local-bottom/ab-overlay inside a built image
# (build-image.sh), and that installed path is what this default used to name --
# so from the moment the source moved to usr/lib/ab/initramfs/ the harness could
# only ever print HARNESS-FAIL. Which is how the most detailed test of the
# riskiest script in the project came to be one nobody ran: it did not fail
# loudly in anyone's build, it simply was not wired to anything.
SCRIPT="${SCRIPT:-/repo/builder/overlay/usr/lib/ab/initramfs/ab-overlay}"
[ -r "$SCRIPT" ] || { echo "HARNESS-FAIL: no $SCRIPT"; exit 1; }
modprobe overlay 2>/dev/null || true

# Every log-based assertion here is paired with a behavioural one. What the
# script did matters more than what it said, and the two fail independently --
# a refusal that works but is never printed leaves an operator with no idea why
# their update did nothing.

WORK=/tmp/abtest
PASS=0; FAIL=0
CASE=""

ok()   { echo "    ok    $*"; PASS=$((PASS+1)); }
bad()  { echo "    FAIL  $*"; FAIL=$((FAIL+1)); }
check(){ ensure_ovl; if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# --- fixture ------------------------------------------------------------------
# A fake root slot with enough shape to be interesting: something the
# distribution owns (/usr/bin/distro-tool), something the machine owns
# (/usr/local/bin/mine), something the image declares it owns (/etc/motd), and
# directories the non-root directives target.
populate_slot() {               # populate_slot <dir>
    mkdir -p "$1"/{usr/bin,usr/local/bin,usr/lib/ab,etc,var/log,var/lib/dpkg,home,opt}
    echo "release-1" > "$1/usr/bin/distro-tool"
    echo "release-1" > "$1/etc/motd"
    echo "release-1" > "$1/var/lib/dpkg/status"
    echo "from-the-image" > "$1/var/log/.shipped"
    printf '/etc/motd\n' > "$1/usr/lib/ab/image-owned.list"
}

make_slot() {
    rm -rf "$WORK/slot"
    mkdir -p "$WORK/slot"
    populate_slot "$WORK/slot"
}

# --- a slot that is a real filesystem -----------------------------------------
#
# Most cases below stand a plain directory in for the root slot, which is enough
# for every directive: the engine binds $rootmnt either way.
#
# It is NOT enough for the reset. The engine decides whether the writable state
# is stale by reading the slot's filesystem UUID -- RAUC makes a fresh filesystem
# for every install, so the UUID changes on exactly the event that invalidates an
# upper. A bound directory has no filesystem of its own: /ab-lower's device in
# /proc/mounts is whatever the container's root is, blkid says nothing about it,
# and the engine falls back to comparing slot letters.
#
# So the directory cases exercise the FALLBACK, which is worth having and is not
# what a real machine does. These helpers give a case two real ext4 filesystems
# to switch between, which is what makes the difference between "boot the other
# slot" and "that slot was reinstalled" visible at all.
SLOT_LOOP=""
CUR_SLOT=""

slot_fs_detach() {
    umount "$WORK/slot" 2>/dev/null || umount -l "$WORK/slot" 2>/dev/null
    [ -n "$SLOT_LOOP" ] && losetup -d "$SLOT_LOOP" 2>/dev/null
    SLOT_LOOP=""; CUR_SLOT=""
}

# A fresh filesystem in that slot: a new UUID, which is what an install looks
# like from here. Must not be the slot currently mounted.
slot_fs_new() {                 # slot_fs_new <A|B>
    [ "$CUR_SLOT" = "$1" ] && slot_fs_detach
    rm -f "$WORK/slot-$1.img"
    truncate -s 96M "$WORK/slot-$1.img"
    mkfs.ext4 -q "$WORK/slot-$1.img" 2>/dev/null
}

slot_fs_use() {                 # slot_fs_use <A|B>  -- mount it as the root slot
    slot_fs_detach
    mkdir -p "$WORK/slot"
    SLOT_LOOP=$(losetup -f --show "$WORK/slot-$1.img")
    mount "$SLOT_LOOP" "$WORK/slot" || echo "    HARNESS-FAIL: could not mount slot $1"
    CUR_SLOT="$1"
}

# The manifest has to be in both slots: the engine reads it from whichever one is
# being booted, and a case that switches slots would otherwise find no manifest
# on the second and silently get the no-manifest defaults.
manifest_both() {               # manifest_both < heredoc
    cat > "$WORK/manifest.tmp"
    local keep="$CUR_SLOT" s
    for s in A B; do
        slot_fs_use "$s"
        mkdir -p "$WORK/slot/usr/lib/ab"
        cp "$WORK/manifest.tmp" "$WORK/slot/usr/lib/ab/state.conf"
    done
    slot_fs_use "$keep"
}

# The overlay partition, for real: the script mounts it by label and the whole
# store layout depends on it being one filesystem, so a tmpfs would not do.
make_ovl() {
    [ -n "${LOOP:-}" ] && losetup -d "$LOOP" 2>/dev/null
    # Every case makes a filesystem labelled "overlay", and the engine finds it
    # with `blkid -L overlay`. Two things then conspire: a loop device that
    # failed to detach still carries the label, and blkid answers from a cache.
    # Between them a case could be handed the *previous* case's partition --
    # which looked like ten unrelated bugs in the engine, all in the later
    # cases, all reproducible, none real.
    losetup -D 2>/dev/null
    rm -f /run/blkid/blkid.tab /run/blkid/blkid.tab.old /etc/blkid.tab 2>/dev/null
    rm -f "$WORK/ovl.img"; mkdir -p "$WORK/ovlmnt"
    truncate -s 512M "$WORK/ovl.img"
    mkfs.ext4 -q -L overlay "$WORK/ovl.img" 2>/dev/null
    LOOP=$(losetup -f --show "$WORK/ovl.img")
    # Assert it, rather than trusting it. This harness exists because this
    # project has twice been fooled by a test that was not testing anything.
    local found; found=$(blkid -L overlay 2>/dev/null)
    if [ "$found" != "$LOOP" ]; then
        echo "    HARNESS-FAIL: blkid -L overlay = '$found', expected '$LOOP'"
        FAIL=$((FAIL+1))
    fi
}

set_cmdline() {                 # set_cmdline "<contents>"
    echo "$1" > "$WORK/cmdline"
    mount -o bind "$WORK/cmdline" /proc/cmdline 2>/dev/null
}

# Unmount everything the engine created, deepest first, and keep going until
# /proc/mounts is clean. Two things make this fussier than it looks: a case can
# stack several mounts on the same path (one per run_engine call), and a lazy
# umount returns before the filesystem is actually free -- which is what made an
# earlier version of this harness detach the loop device out from under a still
# busy /ab-rw and report failures that were not in the code under test.
unmount_all() {
    umount /proc/cmdline 2>/dev/null
    local i m mounts
    for i in $(seq 1 12); do
        mounts=$(awk -v w="$WORK/root" \
            '$2 == w || index($2, w "/") == 1 || $2 ~ /^\/ab-(lower|rw)($|\/)/ { print $2 }' \
            /proc/mounts | sort -r)
        [ -z "$mounts" ] && return 0
        for m in $mounts; do
            umount "$m" 2>/dev/null || umount -l "$m" 2>/dev/null
        done
    done
    echo "    HARNESS-WARN: could not fully unmount:"
    awk '{print "      " $2}' /proc/mounts | grep -E "ab-(lower|rw)|$WORK/root"
}

# Between runs inside one case: drop the mounts but keep the overlay partition
# attached, because the next boot in that case has to find the same one.
teardown() { unmount_all; }

# End of a case: also release the loop device.
finish() {
    unmount_all
    slot_fs_detach
    [ -n "${LOOP:-}" ] && losetup -d "$LOOP" 2>/dev/null
    LOOP=""
}

# Run the real script the way local-bottom does: $rootmnt set, root slot already
# mounted there. A bind of a directory stands in for the slot's filesystem in
# most cases -- the script binds $rootmnt anyway.
#
# It does see the difference in one place, which this comment used to deny: the
# reset reads the slot's filesystem UUID, and a bound directory has none. Cases
# that care use slot_fs_use to mount a real ext4 instead.
run_engine() {                  # run_engine "<cmdline>"
    mkdir -p "$WORK/root"
    mount -o bind "$WORK/slot" "$WORK/root"
    set_cmdline "$1"
    # msg() prefers /dev/kmsg, which in a privileged container is the real
    # kernel ring buffer -- so by default almost nothing the script says reaches
    # stdout. Three ways of getting it back were wrong before this one:
    #
    #   a regular file bound over /dev/kmsg keeps only the last line, because
    #   msg() uses `>` and each message truncates the one before;
    #   a directory does not bind over a device node at all, and with the error
    #   suppressed that looked exactly like it had worked;
    #   reading the ring buffer back with dmesg loses lines to printk rate
    #   limiting, which no sysctl here reliably turns off (23 of 40 survived).
    #
    # /dev/full is a character device whose every write fails with ENOSPC. Bound
    # over /dev/kmsg it sends msg() down the fallback branch it already has, so
    # the whole log arrives on stdout, in order, with nothing dropped.
    mount -o bind /dev/full /dev/kmsg 2>/dev/null
    rootmnt="$WORK/root" sh "$SCRIPT" > "$WORK/out.log" 2>&1
    ENGINE_RC=$?
    umount /dev/kmsg 2>/dev/null
}

# After a refusal the engine unmounts the overlay partition, which is correct --
# it is leaving the machine as it found it -- but it also means an assertion
# about what is on that partition has nothing to read. Put it back first.
ensure_ovl() {
    awk '$2 == "/ab-rw" { found = 1 } END { exit !found }' /proc/mounts && return 0
    [ -n "${LOOP:-}" ] && mount "$LOOP" /ab-rw 2>/dev/null
    return 0
}

# The container's own root is overlayfs, so "is / an overlay" cannot be asked
# with findmnt FSTYPE -- a plain bind of a directory answers "overlay" too, and
# an earlier version of this harness recorded four passes that were nothing of
# the kind. The engine names its mounts, so ask for the name instead.
#
# tail -1 because a case can stack several mounts on one path and findmnt prints
# every one of them; the last is the one the machine actually sees.
is_ab_overlay() { [ "$(findmnt -no SOURCE "$1" 2>/dev/null | tail -1)" = ab-root ]; }

begin() { CASE="$1"; echo ""; echo "== $CASE"; unmount_all; make_slot; make_ovl; }

# Same, but the root slot is a real filesystem in each of two slots. make_ovl
# runs `losetup -D`, so it has to happen while no slot loop is attached --
# otherwise it either detaches the slot out from under the case or trips over a
# busy device, both of which look like engine bugs and are not.
begin_fs() {
    CASE="$1"; echo ""; echo "== $CASE"
    unmount_all
    slot_fs_detach
    make_ovl
    slot_fs_new A; slot_fs_new B
    slot_fs_use B; populate_slot "$WORK/slot"
    slot_fs_use A; populate_slot "$WORK/slot"
}

R="$WORK/root"

# =============================================================================
begin "no manifest at all (an image built before this existed)"
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "root became an overlay"          'is_ab_overlay "$R"'
check "the slot content shows through"  '[ "$(cat "$R/usr/bin/distro-tool")" = release-1 ]'
check "writes land on the partition"    'echo x > "$R/home/f" && [ -f /ab-rw/upper/home/f ]'
check "legacy upper/work paths used"    '[ -d /ab-rw/upper ] && [ -d /ab-rw/work ]'
check "the model was recorded"          '[ "$(cat /ab-rw/.model)" = overlay ]'
finish

# =============================================================================
begin "the default manifest, written out explicitly"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
reset-on-update /usr
reset-on-update /var/lib/dpkg
keep /usr/local
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "root became an overlay"          'is_ab_overlay "$R"'
check "upperdir is the shared upper"    'echo x > "$R/etc/f" && [ -f /ab-rw/upper/etc/f ]'
finish

# =============================================================================
begin "slot change clears OS paths, keeps /usr/local, drops image-owned files"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
reset-on-update /usr
reset-on-update /var/lib/dpkg
keep /usr/local
EOF
# Boot A, then write the three kinds of file a slot change has to tell apart.
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "stale"   > "$R/usr/bin/distro-tool"     # the OS's -- must be dropped
echo "mine"    > "$R/usr/local/bin/mine"      # the machine's -- must survive
echo "machine" > "$R/etc/motd"                # image-owned -- must be dropped
echo "mine"    > "$R/home/keep-me"            # the machine's -- must survive
teardown
# ...now boot B off the same partition.
run_engine "root=LABEL=rootfs-b rauc.slot=B"
check "OS path cleared, image shows"    '[ "$(cat "$R/usr/bin/distro-tool")" = release-1 ]'
check "/usr/local survived the clear"   '[ "$(cat "$R/usr/local/bin/mine")" = mine ]'
check "image-owned file reverted"       '[ "$(cat "$R/etc/motd")" = release-1 ]'
check "/home untouched"                 '[ "$(cat "$R/home/keep-me")" = mine ]'
check "dpkg state cleared"              '[ "$(cat "$R/var/lib/dpkg/status")" = release-1 ]'
check "no keep-aside left behind"       '[ ! -d /ab-rw/.keep ]'
finish

# =============================================================================
begin "ab.state=off boots the slot untouched"
run_engine "root=LABEL=rootfs-a rauc.slot=A ab.state=off"
check "root is not an overlay"          '! is_ab_overlay "$R"'
check "the partition was left alone"    '[ ! -d /ab-rw/upper ]'
finish

# =============================================================================
begin "ab.overlay=off still works (the old spelling)"
run_engine "root=LABEL=rootfs-a rauc.slot=A ab.overlay=off"
check "root is not an overlay"          '! is_ab_overlay "$R"'
finish

# =============================================================================
begin "ab.state=reset sets every store aside"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
persist /home
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "bad-edit" > "$R/etc/motd"
echo "data"     > "$R/home/mine"
teardown
run_engine "root=LABEL=rootfs-a rauc.slot=A ab.state=reset"
check "the bad edit is gone"            '[ "$(cat "$R/etc/motd")" = release-1 ]'
check "upper.prev holds the old upper"  '[ "$(cat /ab-rw/upper.prev/etc/motd)" = bad-edit ]'
check "persist.prev holds the old home" '[ "$(cat /ab-rw/persist.prev/home/mine)" = data ]'
check "/home is clean but seeded"       '[ ! -f "$R/home/mine" ]'
finish

# =============================================================================
begin "a second reset refuses rather than destroying the first snapshot"
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "first" > "$R/etc/motd"
teardown
run_engine "root=LABEL=rootfs-a rauc.slot=A ab.state=reset"
echo "second" > "$R/etc/motd"
teardown
run_engine "root=LABEL=rootfs-a rauc.slot=A ab.state=reset"
check "refusal was logged"              'grep -q "reset refused" "$WORK/out.log"'
check "the first snapshot survived"     '[ "$(cat /ab-rw/upper.prev/etc/motd)" = first ]'
check "the reset did not happen"        '[ "$(cat /ab-rw/upper/etc/motd)" = second ]'
check "no second snapshot was made"     '[ ! -e /ab-rw/upper.prev.prev ]'
finish

# =============================================================================
begin "persist: a shared bind, seeded from the image"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
persist /var/log
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "/var/log is a bind, not overlay" '[ "$(findmnt -no FSTYPE "$R/var/log")" = ext4 ]'
check "seeded from the image copy"      '[ -f "$R/var/log/.shipped" ]'
check "writes go to the persist store"  'echo x > "$R/var/log/syslog" && [ -f /ab-rw/persist/var/log/syslog ]'
check "not in the overlay upper"        '[ ! -f /ab-rw/upper/var/log/syslog ]'
finish

# =============================================================================
begin "persist survives a slot change (that is the point of it)"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
persist /var/log
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "a-logs" > "$R/var/log/syslog"
teardown
run_engine "root=LABEL=rootfs-b rauc.slot=B"
check "slot B sees slot A's logs"       '[ "$(cat "$R/var/log/syslog")" = a-logs ]'
finish

# =============================================================================
begin "slot-private: each slot gets its own copy"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
slot-private /var/log
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "a-logs" > "$R/var/log/syslog"
check "A writes to its own store"       '[ -f /ab-rw/slots/A/var/log/syslog ]'
teardown
run_engine "root=LABEL=rootfs-b rauc.slot=B"
check "B does not see A's logs"         '[ ! -f "$R/var/log/syslog" ]'
check "B is still seeded from the image" '[ -f "$R/var/log/.shipped" ]'
echo "b-logs" > "$R/var/log/syslog"
check "B writes to its own store"       '[ -f /ab-rw/slots/B/var/log/syslog ]'
check "A's copy is still there"         '[ "$(cat /ab-rw/slots/A/var/log/syslog)" = a-logs ]'
finish

# =============================================================================
# The image ships no /var/lib/docker -- docker is not installed yet -- and that
# is the normal case for the paths people most want kept apart. An earlier
# version skipped the store when the image had nothing to seed from, so the bind
# had no source, failed, and the writes went to the shared overlay instead: the
# directive read as applied and the two slots shared the directory anyway.
begin "slot-private for a path the image does not ship"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
slot-private /var/lib/docker
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "the store was created empty"     '[ -d /ab-rw/slots/A/var/lib/docker ]'
check "it is a bind, not the overlay"   '[ "$(findmnt -no SOURCE "$R/var/lib/docker" 2>/dev/null | tail -1)" != ab-root ]'
echo "a-data" > "$R/var/lib/docker/f"
check "writes reach the slot store"     '[ -f /ab-rw/slots/A/var/lib/docker/f ]'
check "nothing reached the shared upper" '[ ! -f /ab-rw/upper/var/lib/docker/f ]'
teardown
run_engine "root=LABEL=rootfs-b rauc.slot=B"
check "slot B does not see A's data"    '[ ! -f "$R/var/lib/docker/f" ]'
finish

# =============================================================================
begin "persist for a path the image does not ship"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
persist /srv/data
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "the store was created empty"     '[ -d /ab-rw/persist/srv/data ]'
echo "a-data" > "$R/srv/data/f"
check "writes reach the persist store"  '[ -f /ab-rw/persist/srv/data/f ]'
teardown
run_engine "root=LABEL=rootfs-b rauc.slot=B"
check "slot B sees it (shared)"         '[ "$(cat "$R/srv/data/f")" = a-data ]'
finish

# =============================================================================
# The overlay partition ships at its minimum and is not grown until
# first-boot-expand runs, long after this. Seeding more than fits filled it
# partway through and left a truncated /var bound over the real one -- a machine
# that boots, looks almost right, and is missing files nobody thinks to check.
# build-image.sh now refuses to ship such a manifest; this is the other half.
begin "a seed that does not fit is discarded, not half-applied"
mkdir -p "$WORK/slot/bulk"
dd if=/dev/zero of="$WORK/slot/bulk/big" bs=1M count=700 2>/dev/null
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
persist /bulk
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "the failure was reported"        'grep -q "could not seed" "$WORK/out.log"'
check "no partial store was left"       '[ ! -e /ab-rw/persist/bulk ] && [ ! -e /ab-rw/persist/bulk.new ]'
check "the path was left on the slot"   '[ "$(findmnt -no SOURCE "$R/bulk" 2>/dev/null | tail -1)" != ext4 ]'
check "the image copy is still readable" '[ -f "$R/bulk/big" ]'
check "the rest of the manifest applied" 'is_ab_overlay "$R"'
finish

# =============================================================================
begin "volatile: a tmpfs that keeps nothing"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
volatile /var/log
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "/var/log is a tmpfs"             '[ "$(findmnt -no FSTYPE "$R/var/log")" = tmpfs ]'
echo "x" > "$R/var/log/syslog"
check "nothing reached the partition"   '[ ! -f /ab-rw/upper/var/log/syslog ]'
teardown
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "gone after a reboot"             '[ ! -f "$R/var/log/syslog" ]'
finish

# =============================================================================
begin "volatile with a size cap"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
volatile /var/log 16M
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "the cap was applied"             'findmnt -no OPTIONS "$R/var/log" | grep -q "size=16"'
finish

# =============================================================================
begin "reset-on-update reaches into a persist store, not just the upper layer"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
persist /var
reset-on-update /usr
reset-on-update /var/lib/dpkg
keep /usr/local
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "stale" > "$R/var/lib/dpkg/status"
echo "mine"  > "$R/var/lib/mine"
check "it went to the persist store"    '[ -f /ab-rw/persist/var/lib/dpkg/status ]'
teardown
run_engine "root=LABEL=rootfs-b rauc.slot=B"
check "dpkg state cleared from persist" '[ "$(cat "$R/var/lib/dpkg/status")" = release-1 ]'
check "the machine's own file survived" '[ "$(cat "$R/var/lib/mine")" = mine ]'
finish

# =============================================================================
begin "stateful model: read-only root, /etc overlaid, /var and /home persisted"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model stateful
overlay /etc
persist /home
persist /var
persist /usr/local
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "root is NOT an overlay"          '! is_ab_overlay "$R"'
check "/etc is an overlay"              'is_ab_overlay "$R/etc"'
check "/home is a bind"                 '[ "$(findmnt -no FSTYPE "$R/home")" = ext4 ]'
check "/usr is untouched by any store"  '[ "$(cat "$R/usr/bin/distro-tool")" = release-1 ]'
check "editing /etc lands in upper"     'echo x > "$R/etc/f" && [ -f /ab-rw/upper/etc/f ]'
check "the model was recorded"          '[ "$(cat /ab-rw/.model)" = stateful ]'
finish

# =============================================================================
begin "a model change delivered by an update is refused, not applied"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "mine" > "$R/home/keep-me"
teardown
# The same partition, now booting an image whose manifest says something else.
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model stateful
overlay /etc
persist /home
EOF
run_engine "root=LABEL=rootfs-b rauc.slot=B"
check "the change was refused"          'grep -q "REFUSING" "$WORK/out.log"'
check "the recorded model is unchanged" '[ "$(cat /ab-rw/.model)" = overlay ]'
check "no store for the new model"      '[ ! -d /ab-rw/persist ]'
check "root is not an overlay"          '! is_ab_overlay "$R"'
check "/home was not rebound"           '[ "$(findmnt -no FSTYPE "$R/home" 2>/dev/null | tail -1)" != ext4 ]'
finish

# =============================================================================
begin "an interrupted keep-aside is finished on the next boot"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
reset-on-update /usr
keep /usr/local
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "mine" > "$R/usr/local/bin/mine"
# Simulate losing power between the move-aside and the move-back.
mkdir -p /ab-rw/.keep
printf '/ab-rw/upper/usr/local\n' > /ab-rw/.keep/1.path
mv /ab-rw/upper/usr/local /ab-rw/.keep/1.data
teardown
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "the held-back path came back"    '[ "$(cat "$R/usr/local/bin/mine")" = mine ]'
check "the staging area was cleaned up" '[ ! -d /ab-rw/.keep ]'
finish

# =============================================================================
begin "a manifest cannot escape its store with .."
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
EOF
# /../../etc/shadow resolves, under the store prefix, to the host's own
# /etc/shadow. A sentinel there proves the guard runs before the path is used
# rather than merely being present in the source.
printf '/../../etc/ab-sentinel\n/etc/motd\n' > "$WORK/slot/usr/lib/ab/image-owned.list"
echo "do-not-delete" > /etc/ab-sentinel
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "machine" > "$R/etc/motd"
teardown
run_engine "root=LABEL=rootfs-b rauc.slot=B"
check "the traversal entry was ignored" '[ "$(cat /etc/ab-sentinel)" = do-not-delete ]'
check "the ordinary entry still worked" '[ "$(cat "$R/etc/motd")" = release-1 ]'
finish

# =============================================================================
# --- upper per-slot ----------------------------------------------------------
#
# The point of the option, stated as a test: a configuration change applied
# while running slot A must not be able to stop slot B from booting. Everything
# below is that one property and the ways it can be got wrong.
#
# /etc/bad.conf is the fixture on purpose. It is not in reset-on-update and not
# in image-owned.list, so nothing else in the engine would drop it on a slot
# change -- if it fails to reach slot B, the per-slot upper is the only reason.
begin "per-slot upper: a change made in slot A cannot reach slot B"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
upper per-slot
overlay /
reset-on-update /usr
keep /usr/local
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "root became an overlay"          'is_ab_overlay "$R"'
echo "breaks-the-boot" > "$R/etc/bad.conf"
echo "mine"            > "$R/home/a-file"
check "A writes to its own upper"       '[ -f /ab-rw/upper-A/etc/bad.conf ]'
check "no shared upper was created"     '[ ! -e /ab-rw/upper ]'
teardown
run_engine "root=LABEL=rootfs-b rauc.slot=B"
check "B never sees the bad config"     '[ ! -e "$R/etc/bad.conf" ]'
check "B never sees A's other writes"   '[ ! -e "$R/home/a-file" ]'
echo "b-only" > "$R/etc/bad.conf"
check "B writes to its own upper"       '[ "$(cat /ab-rw/upper-B/etc/bad.conf)" = b-only ]'
check "A's upper was not touched"       '[ "$(cat /ab-rw/upper-A/etc/bad.conf)" = breaks-the-boot ]'
check "the layout was recorded"         '[ "$(cat /ab-rw/.model)" = overlay+per-slot-upper ]'
finish

# =============================================================================
# The same fixture without the directive. Without this the case above would pass
# just as happily against an engine that had lost the ability to share anything
# at all, which is the failure this project keeps rediscovering: a test that
# cannot fail.
begin "the shared upper still carries that change across (the contrast)"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
reset-on-update /usr
keep /usr/local
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "breaks-the-boot" > "$R/etc/bad.conf"
check "A writes to the shared upper"    '[ -f /ab-rw/upper/etc/bad.conf ]'
teardown
run_engine "root=LABEL=rootfs-b rauc.slot=B"
check "B does see it, as it always has" '[ "$(cat "$R/etc/bad.conf")" = breaks-the-boot ]'
check "no per-slot store was created"   '[ ! -e /ab-rw/upper-A ] && [ ! -e /ab-rw/upper-B ]'
finish

# =============================================================================
# Separating the uppers separates /home too, which is rarely what anyone wants.
# --persist is the answer, and it has to keep working alongside the directive.
begin "per-slot upper: persist is how a path stays shared anyway"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
upper per-slot
overlay /
persist /home
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "data"    > "$R/home/alice"
echo "a-only"  > "$R/etc/bad.conf"
teardown
run_engine "root=LABEL=rootfs-b rauc.slot=B"
check "/home crossed to the other slot" '[ "$(cat "$R/home/alice")" = data ]'
check "/etc did not"                    '[ ! -e "$R/etc/bad.conf" ]'
finish

# =============================================================================
# A per-slot upper does not remove the need to claw back OS paths on a slot
# change. Slot B's upper holds whatever B wrote the last time it ran, which is
# the *previous* release -- so after an update replaces B's rootfs, those files
# shadow the ones the update just delivered, exactly as a shared upper would.
begin "per-slot upper: a slot change still clears OS paths from that slot's upper"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
upper per-slot
overlay /
reset-on-update /usr
reset-on-update /var/lib/dpkg
keep /usr/local
EOF
run_engine "root=LABEL=rootfs-b rauc.slot=B"
echo "stale" > "$R/usr/bin/distro-tool"       # the old release's -- must be dropped
echo "mine"  > "$R/usr/local/bin/mine"        # the machine's -- must survive
teardown
run_engine "root=LABEL=rootfs-a rauc.slot=A"  # ...run A for a while...
teardown
run_engine "root=LABEL=rootfs-b rauc.slot=B"  # ...and come back to B
check "the stale OS file was cleared"   '[ "$(cat "$R/usr/bin/distro-tool")" = release-1 ]'
check "/usr/local survived in B's upper" '[ "$(cat "$R/usr/local/bin/mine")" = mine ]'
check "it was cleared from upper-B"     '[ ! -e /ab-rw/upper-B/usr/bin/distro-tool ]'
check "no keep-aside left behind"       '[ ! -d /ab-rw/.keep ]'
finish

# =============================================================================
# Switching the upper layout is the same fault as switching the model: every
# write the machine has made is in the store the old layout used, and applying
# the new one would show the operator an empty machine. Both directions.
begin "turning the per-slot upper on by update is refused, not applied"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "mine" > "$R/home/keep-me"
teardown
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
upper per-slot
overlay /
EOF
run_engine "root=LABEL=rootfs-b rauc.slot=B"
check "the change was refused"          'grep -q "REFUSING" "$WORK/out.log"'
check "the reason names the upper"      'grep -q "Only the upper layer differs" "$WORK/out.log"'
check "the recorded layout is unchanged" '[ "$(cat /ab-rw/.model)" = overlay ]'
check "root is not an overlay"          '! is_ab_overlay "$R"'
check "no per-slot store was created"   '[ ! -e /ab-rw/upper-B ]'
check "the machine's data is untouched" '[ "$(cat /ab-rw/upper/home/keep-me)" = mine ]'
finish

# =============================================================================
begin "turning the per-slot upper off by update is refused too"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
upper per-slot
overlay /
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "mine" > "$R/home/keep-me"
teardown
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
overlay /
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "the change was refused"          'grep -q "REFUSING" "$WORK/out.log"'
check "the recorded layout is unchanged" '[ "$(cat /ab-rw/.model)" = overlay+per-slot-upper ]'
check "root is not an overlay"          '! is_ab_overlay "$R"'
check "the machine's data is untouched" '[ "$(cat /ab-rw/upper-A/home/keep-me)" = mine ]'
finish

# =============================================================================
# The reset entry exists to get out from under a bad edit. Under a per-slot
# upper the *other* slot's layer is the known-good state someone is reaching for
# when they use it, so wiping that too would destroy the thing being rescued.
begin "per-slot upper: a reset spares the other slot's upper layer"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
upper per-slot
overlay /
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "bad-edit" > "$R/etc/bad.conf"
teardown
run_engine "root=LABEL=rootfs-b rauc.slot=B"
echo "b-good" > "$R/etc/b-marker"
teardown
run_engine "root=LABEL=rootfs-a rauc.slot=A ab.state=reset"
check "slot A starts clean"             '[ ! -e "$R/etc/bad.conf" ]'
check "A's old upper is kept as .prev"  '[ "$(cat /ab-rw/upper-A.prev/etc/bad.conf)" = bad-edit ]'
check "B's upper was left alone"        '[ "$(cat /ab-rw/upper-B/etc/b-marker)" = b-good ]'
check "B got no .prev it did not ask for" '[ ! -e /ab-rw/upper-B.prev ]'
check "it was said out loud"            'grep -q "other slot.s upper layer was left alone" "$WORK/out.log"'
finish

# =============================================================================
# grub.cfg always passes rauc.slot, so this is only reachable from a hand-typed
# command line -- but guessing there would mean handing the machine a layer it
# has never written to, which from inside looks exactly like a wipe.
begin "per-slot upper with no rauc.slot is refused rather than guessed"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
upper per-slot
overlay /
EOF
run_engine "root=LABEL=rootfs-a"
check "the refusal was logged"          'grep -q "no rauc.slot= on the kernel command line" "$WORK/out.log"'
check "root is not an overlay"          '! is_ab_overlay "$R"'
check "no store was invented"           '[ ! -e /ab-rw/upper- ] && [ ! -e /ab-rw/upper ]'
finish

# =============================================================================
# An unrecognised value must not become "per-slot" by accident: that would move
# every existing machine's writes out from under it on the next boot.
begin "an unknown 'upper' value falls back to the shared layer"
cat > "$WORK/slot/usr/lib/ab/state.conf" <<'EOF'
model overlay
upper sometimes
overlay /
EOF
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "it was reported"                 'grep -q "unknown .upper sometimes" "$WORK/out.log"'
check "root became an overlay"          'is_ab_overlay "$R"'
check "the shared upper was used"       'echo x > "$R/etc/f" && [ -f /ab-rw/upper/etc/f ]'
check "the recorded layout is the plain one" '[ "$(cat /ab-rw/.model)" = overlay ]'
finish

# =============================================================================
# Everything above stands a directory in for the root slot, so the engine cannot
# read a filesystem UUID and falls back to comparing slot letters. These cases
# give it two real filesystems, which is the only way to tell "you booted the
# other slot" apart from "that slot was reinstalled" -- and the difference
# between them is the whole reason the reset was rewritten.
#
# First, the guard. If the identity were unreadable here too, every case below
# would quietly re-test the fallback and pass while proving nothing. The engine
# records what it reconciled against, so the presence of that stamp is proof the
# real path was taken.
begin_fs "the slot identity is readable at all (or the cases below prove nothing)"
manifest_both <<'EOF'
model overlay
overlay /
upper per-slot
reset-on-update /usr
reset-on-update /var/lib/dpkg
keep /usr/local
EOF
slot_fs_use A
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "the engine recorded an identity for A's upper" \
      '[ -s /ab-rw/.lower-upper-A ]'
check "and it is the slot filesystem's own UUID" \
      '[ "$(cat /ab-rw/.lower-upper-A)" = "$(blkid -c /dev/null -o value -s UUID "$SLOT_LOOP")" ]'
check "so the reset did not decide by slot letter" \
      '! grep -q "slot changed" "$WORK/out.log"'
finish

# =============================================================================
# The bug. upper-B is written against B's lower; booting A and back into B
# changes the slot letter twice and changes B's image not at all. The old rule
# cleared upper-B on that second switch, every time -- so the one thing a
# per-slot upper is for, each slot keeping its own state, was the thing it did
# not do.
begin_fs "per-slot upper: returning to a slot whose image is unchanged keeps its state"
manifest_both <<'EOF'
model overlay
overlay /
upper per-slot
reset-on-update /usr
reset-on-update /var/lib/dpkg
keep /usr/local
EOF
slot_fs_use B
run_engine "root=LABEL=rootfs-b rauc.slot=B"
echo "installed-by-hand" > "$R/usr/bin/extra-tool"
check "B's own upper holds it"          '[ -f /ab-rw/upper-B/usr/bin/extra-tool ]'
teardown
slot_fs_use A
run_engine "root=LABEL=rootfs-a rauc.slot=A"
teardown
slot_fs_use B
run_engine "root=LABEL=rootfs-b rauc.slot=B"
check "nothing was cleared on the way back" \
      '! grep -q "clearing OS paths" "$WORK/out.log"'
check "what was installed under B is still there" \
      '[ "$(cat "$R/usr/bin/extra-tool")" = installed-by-hand ]'
check "the distribution's own file is still the image's" \
      '[ "$(cat "$R/usr/bin/distro-tool")" = release-1 ]'
finish

# =============================================================================
# ...and the half that must still happen. A bundle installed into B gives that
# slot a new filesystem, so anything in upper-B was written against an image
# that is no longer there.
begin_fs "per-slot upper: a bundle installed into that slot does clear it"
manifest_both <<'EOF'
model overlay
overlay /
upper per-slot
reset-on-update /usr
reset-on-update /var/lib/dpkg
keep /usr/local
EOF
slot_fs_use B
run_engine "root=LABEL=rootfs-b rauc.slot=B"
echo "installed-by-hand" > "$R/usr/bin/extra-tool"
echo "mine" > "$R/usr/local/bin/keepme"
teardown
slot_fs_use A
run_engine "root=LABEL=rootfs-a rauc.slot=A"
teardown
# The install: a fresh filesystem in B, carrying release-2.
slot_fs_new B
slot_fs_use B
populate_slot "$WORK/slot"
echo "release-2" > "$WORK/slot/usr/bin/distro-tool"
cp "$WORK/manifest.tmp" "$WORK/slot/usr/lib/ab/state.conf"
run_engine "root=LABEL=rootfs-b rauc.slot=B"
check "the reset was announced, and for the right reason" \
      'grep -q "was rewritten" "$WORK/out.log"'
check "the stale hand-installed binary is gone" \
      '[ ! -f "$R/usr/bin/extra-tool" ]'
check "the new release is what the machine now runs" \
      '[ "$(cat "$R/usr/bin/distro-tool")" = release-2 ]'
check "/usr/local was held back from the clearing" \
      '[ "$(cat "$R/usr/local/bin/keepme")" = mine ]'
check "A's upper was not touched" \
      '[ -d /ab-rw/upper-A ]'
finish

# =============================================================================
# A shared upper carries whatever the last-running slot wrote, so switching
# slots always invalidates it. This is the default and was already right; it is
# here because the rewrite had to leave it right.
begin_fs "shared upper: a slot change still clears it"
manifest_both <<'EOF'
model overlay
overlay /
reset-on-update /usr
reset-on-update /var/lib/dpkg
keep /usr/local
EOF
slot_fs_use A
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "installed-by-hand" > "$R/usr/bin/extra-tool"
teardown
slot_fs_use B
run_engine "root=LABEL=rootfs-b rauc.slot=B"
check "the reset was announced"         'grep -q "clearing OS paths" "$WORK/out.log"'
check "what A wrote into /usr is gone"  '[ ! -f "$R/usr/bin/extra-tool" ]'
finish

# =============================================================================
# The other half of not over-clearing: rebooting the same slot, with nothing
# installed, must leave everything alone. Under the old rule this was already
# true, and it is the case that would break first if the identity were computed
# from something that varies per boot rather than per install.
begin_fs "rebooting the same slot changes nothing"
manifest_both <<'EOF'
model overlay
overlay /
reset-on-update /usr
reset-on-update /var/lib/dpkg
keep /usr/local
EOF
slot_fs_use A
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "installed-by-hand" > "$R/usr/bin/extra-tool"
teardown
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "nothing was cleared"             '! grep -q "clearing OS paths" "$WORK/out.log"'
check "the file is still there"         '[ "$(cat "$R/usr/bin/extra-tool")" = installed-by-hand ]'
teardown
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "and still there after a third boot" \
      '[ "$(cat "$R/usr/bin/extra-tool")" = installed-by-hand ]'
finish

# =============================================================================
# An update to the running slot cannot happen -- RAUC writes the inactive one --
# but the identity check does not know that, and answering it correctly is what
# makes the rule "this slot's image changed" rather than "the slot letter
# changed". A shared upper whose slot was reinstalled underneath it is stale.
begin_fs "shared upper: the same slot, reinstalled, is still cleared"
manifest_both <<'EOF'
model overlay
overlay /
reset-on-update /usr
reset-on-update /var/lib/dpkg
keep /usr/local
EOF
slot_fs_use A
run_engine "root=LABEL=rootfs-a rauc.slot=A"
echo "installed-by-hand" > "$R/usr/bin/extra-tool"
teardown
slot_fs_new A
slot_fs_use A
populate_slot "$WORK/slot"
cp "$WORK/manifest.tmp" "$WORK/slot/usr/lib/ab/state.conf"
run_engine "root=LABEL=rootfs-a rauc.slot=A"
check "the reset was announced"         'grep -q "was rewritten" "$WORK/out.log"'
check "the stale file is gone"          '[ ! -f "$R/usr/bin/extra-tool" ]'
finish

# =============================================================================
echo ""
echo "================================================"
echo "  passed: $PASS   failed: $FAIL"
echo "================================================"
[ "$FAIL" -eq 0 ]
