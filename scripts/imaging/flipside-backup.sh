#!/bin/bash
# Back up or restore everything this server cannot rebuild, without the web UI.
#
#   ./scripts/flipside-backup.sh backup [FILE]     # default: ./flipside-backup-<date>.tar.gz
#   ./scripts/flipside-backup.sh restore FILE
#   ./scripts/flipside-backup.sh list FILE
#
# The API can do this too (Settings -> Backup), and normally should. This exists
# for the case the API cannot help with: the web UI will not start, or has not
# been installed yet, or the machine it ran on is gone and there is a new one
# with the repository checked out and nothing else. A disaster-recovery
# procedure that requires the thing being recovered is not one.
#
# THE ARCHIVE CONTAINS THE UPDATE SIGNING KEY, every password hash, every live
# API token, and the secrets-manager token. Treat the file as you would treat
# key.pem itself: losing key.pem means no machine already deployed can ever be
# updated again, and leaking it means anyone can sign an update those machines
# will install.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${1:-}"
FILE="${2:-}"

# Kept in step with app/backup.py by the test: a path added there and forgotten
# here produces a backup that silently omits it, which is only ever discovered
# during a restore.
PATHS=(
    output/rauc-keys
    output/users.json
    output/.sessions.json
    output/.api-tokens.json
    output/fleet
    output/hosts/assignments.json
    output/deployments.jsonl
    output/audit.jsonl
    output/.secrets-store.json
    output/jobs/index.json
    server/.env
    webui/.env
)

usage() { sed -n '2,14p' "$0"; exit "${1:-0}"; }

case "$MODE" in
    -h|--help|"") usage;;
esac

case "$MODE" in
backup)
    FILE="${FILE:-flipside-backup-$(date -u +%Y%m%d-%H%M%S).tar.gz}"
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
    echo "This file contains the signing key and every credential on the server."
    echo "Store it accordingly."
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

    if [ -e "$HERE/output/rauc-keys" ] || [ -e "$HERE/output/users.json" ]; then
        safety="$HERE/pre-restore-$(date -u +%Y%m%d-%H%M%S).tar.gz"
        keep=()
        for p in "${PATHS[@]}"; do [ -e "$HERE/$p" ] && keep+=("$p"); done
        ( umask 077; tar -C "$HERE" -czf "$safety" "${keep[@]}" )
        echo "Current state saved to $safety"
    fi

    ( umask 077; tar -C "$HERE" -xzf "$FILE" )
    echo "Restored from $FILE"
    echo
    echo "Restart both stacks so nothing keeps serving the state that was just"
    echo "replaced:"
    echo "    make webui-down && make webui"
    echo "    make server-down && make server-up"
    ;;

*) usage 1;;
esac
