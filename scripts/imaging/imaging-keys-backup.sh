#!/bin/bash
# Back up or restore the imaging state that is NOT in the database.
#
#   ./scripts/imaging/imaging-keys-backup.sh backup [FILE]
#   ./scripts/imaging/imaging-keys-backup.sh restore FILE
#   ./scripts/imaging/imaging-keys-backup.sh list FILE
#
# This is deliberately a small archive, and the small part is the important
# part. Machines, rollouts, users, sessions, tokens and the audit log all live
# in Postgres and are covered by the encrypted database backup (Settings ->
# Backup, docs/disaster-recovery.md). What follows is what that backup does not
# and cannot contain: files on the artefact volume and the provisioning stack's
# configuration.
#
# THE ARCHIVE CONTAINS THE UPDATE SIGNING KEY. Treat the file as you would treat
# key.pem itself. Losing key.pem means no machine already deployed can ever be
# updated again -- not "until we re-key", ever, because those machines verify
# against a certificate baked into their own image. Leaking it means anyone can
# sign an update that every one of them will install without complaint.
#
# It exists as a script, rather than only as an API call, for the case the API
# cannot help with: the server will not start, or the machine it ran on is gone
# and there is a new one with the repository checked out and nothing else. A
# disaster-recovery procedure that requires the thing being recovered is not one.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/../.." && pwd)"
MODE="${1:-}"
FILE="${2:-}"

# Only what the database backup cannot hold. Everything omitted here is omitted
# because it is a row somewhere, not because it was forgotten:
#
#   rauc-keys          the signing key and its certificate. Irreplaceable.
#   hosts/assignments  which MAC gets which hostname when it is imaged.
#   server/.env        the provisioning stack's network configuration.
#
# Built images and bundles are NOT here on purpose. They are large, and they are
# reproducible from the builder given the same inputs -- unlike the key, which is
# not reproducible from anything.
PATHS=(
    output/rauc-keys
    output/hosts/assignments.json
    server/.env
)

usage() { sed -n '2,8p' "$0"; exit "${1:-0}"; }

case "$MODE" in
    -h|--help|"") usage;;
esac

case "$MODE" in
backup)
    FILE="${FILE:-imaging-keys-$(date -u +%Y%m%d-%H%M%S).tar.gz}"
    present=()
    for p in "${PATHS[@]}"; do
        [ -e "$HERE/$p" ] && present+=("$p")
    done
    [ ${#present[@]} -gt 0 ] || { echo "nothing to back up in $HERE" >&2; exit 1; }
    # umask before creating it, not chmod after: between creating a world-
    # readable file and fixing it there is a window, and what is in this one
    # makes that window worth closing.
    ( umask 077
      tar -C "$HERE" -czf "$FILE" "${present[@]}" )
    echo "Wrote $FILE"
    tar -tzf "$FILE" | sed 's/^/  /'
    if [ ! -e "$HERE/output/rauc-keys/key.pem" ]; then
        echo
        echo "WARNING: no output/rauc-keys/key.pem here, so this backup does not"
        echo "         contain the update signing key. Machines already deployed"
        echo "         accept only bundles signed by it; if this server ever had"
        echo "         one, find that backup instead." >&2
    fi
    echo
    echo "This file contains the update signing key. Store it accordingly, and"
    echo "remember it is only half of a restore -- the database backup is the"
    echo "other half (docs/disaster-recovery.md)."
    ;;

list)
    [ -n "$FILE" ] || usage 1
    tar -tzvf "$FILE"
    ;;

restore)
    [ -n "$FILE" ] || usage 1
    [ -f "$FILE" ] || { echo "no such file: $FILE" >&2; exit 1; }
    # Read the whole archive before writing any of it. A truncated or corrupt
    # backup discovered halfway through leaves a server holding half of one
    # state and half of another, which is worse than either.
    tar -tzf "$FILE" >/dev/null || { echo "$FILE is not a readable archive" >&2; exit 1; }

    if [ -e "$HERE/output/rauc-keys" ]; then
        safety="$HERE/pre-restore-$(date -u +%Y%m%d-%H%M%S).tar.gz"
        keep=()
        for p in "${PATHS[@]}"; do [ -e "$HERE/$p" ] && keep+=("$p"); done
        ( umask 077; tar -C "$HERE" -czf "$safety" "${keep[@]}" )
        echo "Current state saved to $safety"
    fi

    ( umask 077; tar -C "$HERE" -xzf "$FILE" )
    echo "Restored from $FILE"
    echo
    echo "Restart the provisioning stack so nothing keeps serving the"
    echo "configuration that was just replaced:"
    echo "    make server-down && make server-up"
    ;;

*) usage 1;;
esac
