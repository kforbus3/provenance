#!/bin/bash
# Convenience wrapper: build the builder image and run it to produce an A/B image
# into ./output. All arguments are passed through to build-image.sh.
#
#   ./run.sh --hostname web01 --username admin --password 's3cret' --image-size 8
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUTPUT_DIR:-$HERE/../output}"

# --help must not cost a docker build. The usage text lives in build-image.sh's
# usage() heredoc; print it from there directly instead of building the image
# that would otherwise print it minutes from now.
for a in "$@"; do
    if [ "$a" = "-h" ] || [ "$a" = "--help" ]; then
        echo "All arguments are passed through to build-image.sh, which accepts:"
        echo
        awk '/^Usage: /{p=1} p{if ($0=="EOF") exit; print}' "$HERE/build-image.sh" \
            | sed "s|\$0|./builder/run.sh|"
        exit 0
    fi
done

# Everything below happens inside Docker, so say so up front if it is missing
# or not running — rather than failing partway in with a less helpful error.
if ! command -v docker >/dev/null 2>&1; then
    echo "[run] docker is not installed (or not on PATH). Install Docker first:" >&2
    echo "[run]   https://docs.docker.com/engine/install/" >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "[run] cannot talk to the Docker daemon. Is it running, and does this" >&2
    echo "[run] user have permission to use it (docker group, or sudo)?" >&2
    exit 1
fi

# The builder container runs as the architecture it is building. debootstrap and
# every chroot step then execute natively -- on an arm64 host that makes an arm64
# build as fast as an amd64 one, and on an amd64 host Docker's binfmt handles the
# emulation without build-image.sh needing to know.
ARCH=amd64
prev=""
for a in "$@"; do
    [ "$prev" = "--arch" ] && ARCH="$a"
    prev="$a"
done
case "$ARCH" in
    amd64|arm64) ;;
    *) echo "[run] unsupported --arch '$ARCH' (expected amd64 or arm64)" >&2; exit 2;;
esac
PLATFORM="linux/${ARCH}"
echo "[run] target architecture: $ARCH (builder platform $PLATFORM)"
mkdir -p "$OUT"

# --- will this actually fit on the host? -------------------------------------
#
# Asked here because here is the only place that can answer. Inside the builder,
# `df` reports the size Docker's disk image was *provisioned* at, which on a Mac
# is routinely three times what the host can actually supply: Docker.raw is a
# sparse file, so 228 GB apparent over 37 GB real on a disk with 79 GiB free
# reports ~176 GB available and means ~79. A build that believes that number
# fills the host underneath a VM that never notices, and the failure arrives as
# a corrupted Docker data file rather than ENOSPC -- which is how this project
# lost a Docker installation once already, mid-way through a boot test.
#
# So: check the host, warn, and let the operator decide. Not fatal, because the
# estimate is deliberately crude and being wrong about it must not be the thing
# that stops a build that would have worked.
host_free_gib() {
    # BSD and GNU df disagree on flags but agree on -k and column 4.
    df -k "$1" 2>/dev/null | awk 'NR==2 {printf "%d", $4 / 1048576}'
}

SIZE_ARG=""
prev=""
for a in "$@"; do
    [ "$prev" = "--image-size" ] && SIZE_ARG="$a"
    prev="$a"
done
# `auto` is about 7 GiB with the default slots. Doubled because the build stages
# an uncompressed image and then compresses it, so both exist at once.
case "$SIZE_ARG" in
    ''|auto) NEED=16;;
    *)       NEED=$(( ${SIZE_ARG%%[!0-9]*} * 2 + 2 ));;
esac

FREE="$(host_free_gib "$OUT")"
if [ -n "${FREE:-}" ] && [ "$FREE" -lt "$NEED" ]; then
    echo "[run] WARNING: about ${NEED} GiB is wanted for this build and the host has"
    echo "[run]          ${FREE} GiB free on $(cd "$OUT" && pwd)."
    if [ "$(uname -s)" = "Darwin" ]; then
        RAW="$HOME/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw"
        if [ -f "$RAW" ]; then
            echo "[run]          Docker's VM will report far more than that: its disk image is"
            echo "[run]          sparse and provisioned at $(ls -lh "$RAW" | awk '{print $5}'), of which"
            echo "[run]          $(du -h -d0 "$RAW" 2>/dev/null | awk '{print $1}') is real. The VM cannot see the host filling up, so"
            echo "[run]          running out here corrupts Docker rather than failing cleanly."
        fi
    fi
    echo "[run]          Free space, or use a smaller --image-size, before continuing."
    echo "[run]          Continuing in 10s — Ctrl-C to stop."
    sleep 10
fi

echo "[run] building builder image…"
docker build --platform="$PLATFORM" -t "debian-ab-builder:${ARCH}" "$HERE"

echo "[run] building A/B image into $OUT …"
# overlay.d and any --run-script have to be visible inside the container, so
# both are mounted read-only. Read-only because a build must not be able to
# modify the files it is being customized with.
CUSTOM="$(cd "$HERE/.." && pwd)/overlay.d"
mkdir -p "$CUSTOM"
docker run --rm --privileged \
    --platform="$PLATFORM" \
    -v "$OUT":/output \
    -v "$CUSTOM":/overlay.d:ro \
    "debian-ab-builder:${ARCH}" "$@"

echo "[run] artifacts:"
ls -lh "$OUT"
