#!/bin/bash
# Build the netboot imager (kernel + initramfs) into ./output/imager.
#
#   ./run.sh                # amd64 → output/imager/
#   ./run.sh --arch arm64   # arm64 → output/imager/arm64/
#
# The imager is executed by the machine being provisioned, so it has to be built
# for that machine's architecture: an amd64 imager cannot boot an arm64 box.
set -euo pipefail

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

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUTPUT_DIR:-$HERE/../output}"
mkdir -p "$OUT"

ARCH=amd64
prev=""
for a in "$@"; do
    [ "$prev" = "--arch" ] && ARCH="$a"
    prev="$a"
done
case "$ARCH" in
    amd64) KERNEL_PKG=linux-image-amd64;;
    arm64) KERNEL_PKG=linux-image-arm64;;
    *) echo "[run] unsupported --arch '$ARCH' (expected amd64 or arm64)" >&2; exit 2;;
esac
PLATFORM="linux/${ARCH}"

# Cross-architecture builds run the target's binaries under qemu, which needs an
# interpreter registered with binfmt_misc. Docker does not do it, and without it
# the build fails deep inside with "Exec format error" rather than saying why.
want=x86_64; [ "$ARCH" = arm64 ] && want=aarch64
if [ "$(uname -m)" != "$want" ]; then
    echo "[run] registering qemu-$want so $ARCH can be built on this host"
    docker run --privileged --rm tonistiigi/binfmt --install "$ARCH" >/dev/null \
        || echo "[run] WARNING: could not register binfmt; this build will likely fail"
fi

echo "[run] building the $ARCH imager (platform $PLATFORM)"
docker build --platform="$PLATFORM" --build-arg "KERNEL_PKG=$KERNEL_PKG" \
    -t "debian-ab-imager:${ARCH}" "$HERE"
docker run --rm --platform="$PLATFORM" -e "ARCH=$ARCH" -v "$OUT":/output \
    "debian-ab-imager:${ARCH}"

if [ "$ARCH" = amd64 ]; then
    echo "[run] imager artifacts in $OUT/imager"
else
    echo "[run] imager artifacts in $OUT/imager/$ARCH"
fi
