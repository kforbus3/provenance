#!/bin/bash
# Profile/desktop combinations must be refused at argument-parse time,
# before the builder has allocated, written, or mounted anything.
#
# The failure this prevents: a desktop environment the distro does not package
# (cinnamon on Ubuntu, or a typo) surviving validation and dying inside apt,
# twenty minutes and one debootstrap after the operator stopped watching. The
# refusal has to happen while there is still someone at the other end to read
# it -- and it has to say what IS available for that distro, because the names
# differ between Debian and Ubuntu and guessing spellings is how the typo got
# there in the first place.
#
# Runs build-image.sh directly, unprivileged, with no Docker: every case below
# must die (or pass the profile gate and die on a deliberate bad --arch, which
# sits AFTER the profile validation) before the script touches a loop device,
# a filesystem, or the network. A case that gets far enough to need any of
# those is itself a failure -- it means validation moved later.
#
#   bash scripts/test-profile-args.sh
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="$HERE/../builder/build-image.sh"
[ -r "$BUILD" ] || { echo "HARNESS-FAIL: no $BUILD"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "    ok    $*"; PASS=$((PASS+1)); }
bad() { echo "    FAIL  $*"; FAIL=$((FAIL+1)); }

# Every case runs in an empty directory and must leave it empty: the whole
# point is that a refused build has done no work.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# run_case <expect-substring> <args...>
# Asserts: nonzero exit, the message names the actual problem, and nothing was
# created in the working directory.
run_case() {
    local expect="$1"; shift
    local out rc
    out="$(cd "$WORK" && bash "$BUILD" "$@" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
        bad "$* -- exited 0, expected a refusal"; return
    fi
    # -e keeps an expectation that starts with "--" from being read as a grep
    # option, which is most of them.
    if ! printf '%s' "$out" | grep -qF -e "$expect"; then
        bad "$* -- died, but not with '$expect':"
        printf '%s\n' "$out" | sed 's/^/          /' | tail -5
        return
    fi
    if [ -n "$(ls -A "$WORK")" ]; then
        bad "$* -- refused, but left files behind: $(ls -A "$WORK")"; return
    fi
    ok "$*"
}

echo "== unknown profiles and stray --desktop are refused by name =="
run_case "--profile must be minimal, server or desktop" --profile workstation
run_case "only means anything with --profile desktop"   --desktop kde
run_case "only means anything with --profile desktop"   --profile server --desktop kde
run_case "only means anything with --profile desktop"   --profile minimal --desktop gnome

echo "== an environment the distro does not package lists what it does =="
# Ubuntu has no cinnamon flavour; the refusal must say so and name the ones
# that exist, because the operator's next action is picking one of them.
run_case "Available for ubuntu: gnome kde xfce mate lxqt" \
    --profile desktop --desktop cinnamon --suite noble
run_case "Available for debian: gnome kde xfce mate cinnamon lxqt" \
    --profile desktop --desktop unity
# A distro that is neither is a distro error, not a bogus list of desktops.
run_case "--distro must be debian or ubuntu" \
    --profile desktop --desktop gnome --distro fedora

echo "== valid combinations get PAST the profile gate =="
# The contrast that keeps the cases above honest: with a valid combination the
# script must die later (here: on a deliberately bad --arch, which build-image.sh
# validates after the profile) and its message must not be about profiles. A
# gate that refused everything would pass every case above.
run_case "--arch must be amd64 or arm64" \
    --profile desktop --desktop kde --arch bogus
run_case "--arch must be amd64 or arm64" \
    --profile desktop --suite noble --arch bogus          # default env: gnome
run_case "--arch must be amd64 or arm64" \
    --profile server --arch bogus
run_case "--arch must be amd64 or arm64" \
    --profile minimal --arch bogus

echo ""
echo "================================================"
echo "  passed: $PASS   failed: $FAIL"
echo "================================================"
[ "$FAIL" -eq 0 ]
