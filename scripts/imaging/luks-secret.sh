#!/bin/bash
#
# Generate, store and retrieve an image's LUKS passphrase using OpenBao or
# HashiCorp Vault -- the command-line equivalent of what the web UI does.
#
# The web UI holds this integration properly: it is configured once, generates
# the passphrase, files it, and reads it back when it packages an update bundle.
# This script exists so `./builder/run.sh` is not a second-class path, and it
# writes the same KV v2 payload the UI does, so an image built either way is
# recoverable from the other.
#
#   # generate a passphrase, store it, and stage it for the builder
#   ./scripts/luks-secret.sh new debian-trixie-amd64-ab.img
#   ./builder/run.sh --encrypt --unlock tpm2 \
#       --luks-passphrase-file /output/.luks-pass \
#       --output /output/debian-trixie-amd64-ab.img
#   ./scripts/luks-secret.sh clean
#
# The passphrase is staged in a file rather than passed as an argument because
# arguments are visible in `ps` to every user on the build host. output/ is
# already mounted into the builder, so the file needs no extra plumbing; it is
# written 0600 and `clean` removes it.
#
# Configuration comes from the environment, as the bao/vault CLIs expect:
#   BAO_ADDR / VAULT_ADDR      store address        (required)
#   BAO_TOKEN / VAULT_TOKEN    token                (required unless already logged in)
#   BAO_NAMESPACE / VAULT_NAMESPACE                 (optional)
#   LUKS_KV_MOUNT              KV v2 mount          (default: secret)
#   LUKS_KV_PREFIX             path prefix          (default: debian-ab-images)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$HERE/../output}"
STAGED="$OUTPUT_DIR/.luks-pass"
# The path the *builder* sees. output/ is bind-mounted at /output, so the host
# path above and this one are the same file under different names.
STAGED_IN_CONTAINER="/output/.luks-pass"

MOUNT="${LUKS_KV_MOUNT:-secret}"
PREFIX="${LUKS_KV_PREFIX:-debian-ab-images}"

die() { echo "[luks-secret] ERROR: $*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: $0 <command> [image]

  new <image>     Generate a passphrase, store it, and stage it for the builder.
                  Prints the path to pass to --luks-passphrase-file.
  stage <image>   Stage the passphrase already stored for <image> (for rebuilding
                  a bundle from an existing encrypted image).
  show <image>    Print the stored passphrase on stdout.
  clean           Remove the staged file.

<image> is the image filename, with or without a .zst/.gz suffix.
EOF
}

# OpenBao's CLI is a fork of Vault's and takes the same arguments; whichever is
# installed is the one used, and BAO_* falls back to VAULT_* the way both CLIs
# already do for each other.
find_cli() {
    if command -v bao >/dev/null 2>&1; then echo bao
    elif command -v vault >/dev/null 2>&1; then echo vault
    else die "neither 'bao' nor 'vault' is installed"
    fi
}

# Strip the compression suffix so foo.img and foo.img.zst -- the same image,
# built with different --compress -- resolve to one entry. Matches
# secretstore.secret_name() in the web UI backend.
secret_name() {
    local n="${1##*/}"
    case "$n" in
        *.zst) n="${n%.zst}";;
        *.gz)  n="${n%.gz}";;
    esac
    [ -n "$n" ] || die "image name is empty"
    printf '%s' "$n"
}

# 256 bits, URL-safe: no shell metacharacters to survive the trip through the
# environment, the container and cryptsetup.
gen_passphrase() {
    local raw
    if command -v openssl >/dev/null 2>&1; then
        raw="$(openssl rand -base64 32)"
    else
        raw="$(head -c 32 /dev/urandom | base64)"
    fi
    printf '%s' "$raw" | tr '+/' '-_' | tr -d '=\n'
}

stage() {  # $1=passphrase
    mkdir -p "$OUTPUT_DIR"
    ( umask 077; printf '%s\n' "$1" > "$STAGED" )
    chmod 600 "$STAGED"
}

cmd="${1:-}"
case "$cmd" in
    new|stage|show)
        [ $# -ge 2 ] || { usage; exit 1; }
        CLI="$(find_cli)"
        NAME="$(secret_name "$2")"
        PATH_KV="$MOUNT/${PREFIX:+$PREFIX/}$NAME"
        ;;
    clean)
        rm -f "$STAGED"
        echo "[luks-secret] removed $STAGED"
        exit 0
        ;;
    -h|--help|"") usage; exit 0;;
    *) usage; exit 1;;
esac

case "$cmd" in
    new)
        PASS="$(gen_passphrase)"
        # Stored before anything is built, and the script fails here if the store
        # will not take it. The alternative -- build first, store afterwards --
        # can produce an encrypted image whose recovery key was never persisted,
        # which is not a recoverable mistake.
        "$CLI" kv put "$PATH_KV" \
            passphrase="$PASS" \
            image="$NAME" \
            created="$(date -u +%FT%TZ)" \
            note="LUKS2 recovery passphrase for this A/B image. Every machine imaged from it accepts this passphrase on any encrypted partition." \
            >/dev/null || die "could not write $PATH_KV"
        stage "$PASS"
        echo "[luks-secret] stored at $PATH_KV" >&2
        echo "[luks-secret] staged for the builder; pass:" >&2
        echo "$STAGED_IN_CONTAINER"
        ;;
    stage)
        PASS="$("$CLI" kv get -field=passphrase "$PATH_KV")" \
            || die "no passphrase stored at $PATH_KV"
        stage "$PASS"
        echo "[luks-secret] staged from $PATH_KV" >&2
        echo "$STAGED_IN_CONTAINER"
        ;;
    show)
        "$CLI" kv get -field=passphrase "$PATH_KV" \
            || die "no passphrase stored at $PATH_KV"
        echo
        ;;
esac
