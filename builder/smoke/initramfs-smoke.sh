#!/usr/bin/env bash
# Does the initramfs this build produces actually contain the things a machine
# needs to boot?
#
# Every expensive bug in the RHEL work has been in this step, and the reason is
# structural: an initramfs that is missing a hook, a module or a config file
# builds cleanly, produces a valid image, and fails at boot on a machine that is
# no longer in front of you. A full image build takes half an hour, so the bugs
# were being found one per build.
#
# This reproduces just the initramfs assembly -- the same bootstrap, the same
# overlay files, the same dracut invocation, in a chroot as the real build does
# -- and asserts what came out. It runs in a few minutes and needs no loop
# device, no LUKS and no bootloader.
#
# What it deliberately does NOT do: prove the image boots. It proves the parts
# are present and runnable. That is the difference between "the hook is in the
# initramfs" and "the hook does the right thing at pre-pivot", and only real
# hardware settles the second.
#
# Usage: builder/smoke/initramfs-smoke.sh [suite]     (default 9)
set -euo pipefail

SUITE="${1:-9}"
FAILURES=0

log()  { echo -e "\033[0;32m[smoke]\033[0m $*"; }
fail() { echo -e "\033[0;31m[smoke] FAIL\033[0m $*"; FAILURES=$((FAILURES + 1)); }
pass() { echo -e "\033[0;32m[smoke] PASS\033[0m $*"; }

# rpm scriptlets close every fd up to RLIMIT_NOFILE between fork and exec, and a
# container inherits whatever the daemon had. See build-image.sh for the whole
# story; without this the bootstrap alone takes hours.
ulimit -S -n 65536 2>/dev/null || true
ulimit -H -n 65536 2>/dev/null || true

R=/tmp/smokeroot
rm -rf "$R"; mkdir -p "$R"

cleanup() {
    set +e
    for d in etc/resolv.conf dev proc sys; do
        mountpoint -q "$R/$d" && umount "$R/$d"
    done
}
trap cleanup EXIT

log "bootstrapping a minimal el${SUITE} root"
dnf -y -q --installroot="$R" --releasever="$SUITE" --nogpgcheck \
    --setopt=install_weak_deps=False install dnf systemd passwd >/dev/null 2>&1 \
    || { fail "bootstrap failed"; exit 1; }

# The same resolver handling the real build does: dnf --installroot leaves none,
# so the chroot transaction below cannot resolve its mirror without this.
rm -f "$R/etc/resolv.conf"; : > "$R/etc/resolv.conf"
mount --bind /etc/resolv.conf "$R/etc/resolv.conf"
for d in dev proc sys; do mount --bind "/$d" "$R/$d"; done

log "installing kernel, dracut and cryptsetup in the chroot"
chroot "$R" dnf -y -q install --setopt=install_weak_deps=False \
    kernel-core dracut cryptsetup >/dev/null 2>&1 \
    || { fail "chroot package install failed"; exit 1; }

# The overlay, exactly as build-image.sh applies it.
OVERLAY="$(cd "$(dirname "${BASH_SOURCE[0]}")/../overlay" && pwd)"
cp -a "$OVERLAY"/usr/. "$R/usr/"
chmod 0755 "$R/usr/lib/dracut/modules.d/90ab-overlay/module-setup.sh" \
           "$R/usr/lib/dracut/modules.d/91ab-luks-key/module-setup.sh" \
           "$R/usr/lib/ab/initramfs/ab-overlay" \
           "$R/usr/lib/ab/initramfs/ab-luks-key" 2>/dev/null || true

# The state manifest is what each module's check() looks for to decide this is
# one of our images. Without it the modules opt out -- and if --add stops forcing
# them in, that is exactly how they would silently disappear again.
mkdir -p "$R/usr/lib/ab"
printf 'model overlay\n' > "$R/usr/lib/ab/state.conf"

# A crypttab shaped like the one the builder writes, including the option names.
cat > "$R/etc/crypttab" <<'EOF'
luks-rootfs-a     PARTLABEL=rootfs-a       /cryptkey/luks.key     luks,discard,initramfs,x-initrd.attach
luks-rootfs-b     PARTLABEL=rootfs-b       /cryptkey/luks.key     luks,discard,initramfs,x-initrd.attach
luks-overlay      PARTLABEL=overlay        /cryptkey/luks.key     luks,discard,initramfs,x-initrd.attach
EOF

KVER="$(ls "$R/lib/modules" 2>/dev/null | head -1)"
[ -n "$KVER" ] || { fail "no kernel modules directory; the kernel package did not install"; exit 1; }
log "kernel $KVER"

# Diagnostics BEFORE the run, so a failure below says which half broke: the
# module files not arriving, or dracut declining to use them.
log "module files in the root:"
ls -la "$R/usr/lib/dracut/modules.d/90ab-overlay/" 2>&1 | sed 's/^/         /' || echo "         MISSING"
log "dracut's own module list (ab-*):"
chroot "$R" dracut --list-modules 2>/dev/null | grep -E "^ab-" | sed 's/^/         /' || echo "         not listed (forced by --add, so not fatal on its own)"

log "generating the initramfs with the build's own flags"
chroot "$R" dracut --force --no-hostonly --no-hostonly-cmdline \
    --kver "$KVER" \
    --add "ab-overlay ab-luks-key" \
    --install /etc/crypttab \
    "/boot/initramfs-${KVER}.img" 2>/tmp/dracut.err \
    || { fail "dracut failed"; sed 's/^/         /' /tmp/dracut.err | tail -20; exit 1; }
# dracut warns rather than fails when a module it was told to add contributed
# nothing, so its stderr is the only place that says so.
if grep -qiE "ab-overlay|ab-luks|cannot be found|omitting" /tmp/dracut.err 2>/dev/null; then
    log "dracut had something to say about the modules:"
    grep -iE "ab-overlay|ab-luks|cannot be found|omitting" /tmp/dracut.err | sed 's/^/         /' | head -10
fi

# Inspect it the same way the build does, and distinguish "cannot inspect" from
# "not present" -- conflating those two turns a broken check into a report that
# the image is broken, which is a whole build cycle spent in the wrong place.
LISTING="$(chroot "$R" lsinitrd "/boot/initramfs-${KVER}.img" 2>/dev/null)" || {
    fail "lsinitrd could not read the initramfs; the checks below cannot run"
    exit 1
}
[ -n "$LISTING" ] || { fail "lsinitrd produced no output"; exit 1; }
log "initramfs listing: $(wc -l <<<"$LISTING") entries"

check() {   # check <description> <regex>
    # Herestring, not `printf | grep -q`: under `set -o pipefail` that pipeline
    # returns failure whenever grep -q exits early enough to SIGPIPE the writer,
    # so every check fails no matter what the initramfs contains. That is not a
    # hypothetical -- it is the bug that made this script report six failures on
    # an initramfs that had everything in it.
    if grep -qE "$2" <<<"$LISTING"; then
        pass "$1"
    else
        fail "$1  (no match for /$2/)"
    fi
}

# The hook FILES, matched on the .sh suffix. dracut sources only *.sh from a hook
# directory, so a hook installed under any other name is in the image and inert
# -- which is what inst_hook produced, and what grepping for the MODULE name
# failed to notice for the entire life of this feature.
check "A/B overlay hook is present and runnable" \
      "hooks/pre-pivot/.*ab-overlay\.sh"
check "LUKS bootstrap-key hook is present and runnable" \
      "hooks/initqueue/settled/.*ab-luks-key\.sh"
check "the shared overlay script itself is in the image" \
      "usr/lib/ab/initramfs/ab-overlay"
check "the shared LUKS key script itself is in the image" \
      "usr/lib/ab/initramfs/ab-luks-key"

# Crypt support AND the rule it unlocks by. --no-hostonly means dracut does not
# copy crypttab on its own, and crypt support with no crypttab is an initramfs
# that can open LUKS containers and does not know which ones.
check "crypt support is in the initramfs" "cryptsetup|/crypt"
check "the crypttab is in the initramfs"  "etc/crypttab"

echo
if [ "$FAILURES" -gt 0 ]; then
    # Show the evidence. A failing check that does not print what it looked at
    # costs another run of this whole script to find out.
    echo "[smoke] what the initramfs actually contains, for the things checked above:"
    grep -iE "ab-overlay|ab-luks|crypttab|hooks/pre-pivot|hooks/initqueue" <<<"$LISTING" \
        | sed 's/^/         /' | head -20
    echo "[smoke] (nothing above means none of them are in it at all)"
    echo
    echo -e "\033[0;31m[smoke] $FAILURES check(s) failed\033[0m"
    echo "[smoke] Each one is an image that builds cleanly and does not boot."
    exit 1
fi
echo -e "\033[0;32m[smoke] all initramfs checks passed\033[0m"
