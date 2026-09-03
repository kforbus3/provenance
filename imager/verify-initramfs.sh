#!/bin/bash
# Check that a packed imager initramfs is one a machine can actually boot.
#
#   ./verify-initramfs.sh output/imager/initramfs.img
#
# The build runs this before publishing, and it is worth running by hand against
# a server's live artifact when a machine panics during netboot -- the failure it
# catches looks like nothing at all from the build side.
#
# What it is for. A netbooted machine gets only a kernel and this archive; the
# imager's command line carries no root=, so if the archive does not yield a
# working /init the kernel falls through to /sbin/init, /etc/init, /bin/init,
# /bin/sh and panics with "No working init found". Note there is no "Failed to
# execute /init" line in that case: the kernel prints that only when /init exists
# and cannot be run, and says nothing at all when it is simply absent. So the
# panic that a truncated archive produces names neither the archive nor the file.
set -uo pipefail

IMG="${1:-}"
[ -n "$IMG" ] || { echo "usage: $(basename "$0") <initramfs.img>" >&2; exit 2; }
[ -f "$IMG" ] || { echo "no such file: $IMG" >&2; exit 2; }

fail() { echo -e "\033[0;31m[verify] FAIL:\033[0m $*" >&2; exit 1; }

# A pack killed partway still leaves a valid gzip PREFIX, so the stream has to be
# read to its end to know it is whole.
gzip -t "$IMG" 2>/dev/null \
    || fail "$IMG is not a complete gzip stream (truncated or still being written?)"

LIST="$(mktemp)"
trap 'rm -f "$LIST"' EXIT
# Listed once into a file rather than piped straight into grep: `grep -q` exits at
# its first match and SIGPIPEs the decompressor, which under `set -o pipefail`
# fails the pipeline -- so a piped check reports failure exactly when it passes.
# Paths are normalised: GNU cpio strips the leading "./" that `find .` produces
# and BSD cpio keeps it, so matching one spelling makes this pass or fail on which
# cpio happened to write the archive rather than on what is in it.
gzip -dc "$IMG" | cpio -t --quiet 2>/dev/null | sed 's#^\./##' > "$LIST" \
    || fail "$IMG is not a readable cpio archive"
[ -s "$LIST" ] || fail "$IMG lists no entries at all"

# /init is what the kernel runs; /bin/busybox is the interpreter its shebang
# names. Either one missing is the same panic, so both are checked by name.
grep -qx 'init' "$LIST" \
    || fail "no /init in $IMG — a machine booting this panics with 'No working init found'"
grep -qx 'bin/busybox' "$LIST" \
    || fail "no /bin/busybox in $IMG — /init's interpreter (#!/bin/busybox sh) is missing"

echo "[verify] OK: $(wc -l < "$LIST" | tr -d ' ') entries, /init and /bin/busybox present"
