#!/bin/bash
# Report to the Flipside control plane, and do what it says.
#
#   ab-agent                     # one check-in (what the timer runs)
#   ab-agent --status            # what this machine would report, and to where
#   ab-agent --set-server URL    # point this machine at a different server
#   ab-agent --now               # check in even if ENABLED=0 in the config
#
# This is the machine's half of fleet management, and it is a poll rather than
# anything the server can initiate. The reason is the deployment, not taste: a
# machine is imaged on a private provisioning switch and then moves to wherever
# it is going to live. After that the server does not know this machine's
# address and very likely cannot route to it. So the machine asks, on a timer,
# and the answer is either "nothing to do" or a bundle to install.
#
# Which server it asks is the part that has to survive that move. The imager
# writes the address it provisioned from into /boot/ab-deploy.json -- and that
# address is on the provisioning segment, which this machine leaves. So the
# server URL lives in /etc/flipside/agent.conf, seeded from the marker on first
# run, and thereafter changeable in three ways: by hand here with --set-server,
# by the server itself (it may advertise a better address in any reply, which is
# how a whole fleet gets re-pointed without touching a machine), or by the
# config file being part of an image. /etc is on the overlay in every state
# model, so what is set here survives updates.
set -u

# Overridable so the test harness can point the whole agent at a temp directory
# and drive the real script rather than a copy of it. Nothing on a machine sets
# these; if a test could only exercise a reimplementation, it would be testing
# the reimplementation.
CONF="${AB_AGENT_CONF:-/etc/flipside/agent.conf}"
STATE_DIR="${AB_AGENT_STATE_DIR:-/var/lib/flipside}"
STATE="$STATE_DIR/agent-state"
MARKER="${AB_AGENT_MARKER:-/boot/ab-deploy.json}"
VERSION_FILE="${AB_AGENT_VERSION_FILE:-/usr/lib/flipside/version}"
BOOT_VERSION_DIR="${AB_AGENT_BOOT_DIR:-/boot}"
CMDLINE="${AB_AGENT_CMDLINE:-/proc/cmdline}"
UPDATE_CMD="${AB_AGENT_UPDATE_CMD:-/usr/local/sbin/ab-update.sh}"
AGENT_VERSION=1

# Defaults, overridden by $CONF.
SERVER=""                 # base URL, e.g. https://flipside.example.com
INTERVAL=300              # advisory; the systemd timer is what actually paces us
TOKEN=""                  # sent as X-Flipside-Agent-Token when set
REBOOT=auto               # auto | manual -- whether to reboot after an install
ENABLED=1

log() { logger -t ab-agent -- "$*" 2>/dev/null || true; [ -t 1 ] && echo "$*"; return 0; }
die() { echo "ab-agent: $*" >&2; exit 1; }

# shellcheck source=/dev/null
[ -r "$CONF" ] && . "$CONF"

# ---------------------------------------------------------------- server URL
#
# Seed from the imager's marker only when nothing has been configured. This is
# the machine's first ever check-in, on the provisioning network, where that
# address is still correct -- and being visible for that one beat is worth more
# than waiting to be told a better one.
seed_server() {
    [ -n "$SERVER" ] && return 0
    [ -r "$MARKER" ] || return 0
    SERVER="$(sed -n 's|.*"control_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*|\1|p' "$MARKER")"
    [ -n "$SERVER" ] && return 0
    # Older markers carry only the check-in URL; its origin is the same server.
    # `https*://` rather than `https\?://`: \? is a GNU extension that BSD sed
    # does not implement, and there it silently matches nothing rather than
    # erroring -- so the fallback quietly did nothing at all when the harness
    # ran anywhere but Linux, which is a poor way to find out.
    SERVER="$(sed -n 's|.*"checkin_url"[[:space:]]*:[[:space:]]*"\(https*://[^/]*\)/.*|\1|p' "$MARKER")"
}

save_conf() {
    mkdir -p "$(dirname "$CONF")"
    umask 022
    cat > "$CONF" <<EOF
# Flipside agent configuration. Written by ab-agent --set-server; safe to edit.
SERVER="$SERVER"
INTERVAL=$INTERVAL
TOKEN="$TOKEN"
REBOOT=$REBOOT
ENABLED=$ENABLED
EOF
}

# ------------------------------------------------------------ what we report

machine_id() {
    # The identity the imager reported under, so the server joins this machine
    # to its own imaging history rather than inventing a second row for it.
    local id=""
    [ -r "$MARKER" ] && id="$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$MARKER")"
    if [ -z "$id" ]; then
        for f in /sys/class/net/*/address; do
            case "$f" in */lo/*) continue;; esac
            local a; a="$(cat "$f" 2>/dev/null)"
            case "$a" in ""|00:00:00:00:00:00) continue;; esac
            id="$a"; break
        done
    fi
    echo "$id"
}

running_version() {
    # Two sources, in order, because a slot can arrive two ways.
    #
    # A bundle's install hook writes /boot/<A|B>/ab-version beside the kernel it
    # installed for that slot, so this is the authority once a machine has ever
    # been updated -- and it is per-slot, so a rollback reports the version it
    # rolled back to instead of insisting it is still on the one that failed.
    local slot; slot="$(current_slot)"
    if [ -n "$slot" ] && [ -r "$BOOT_VERSION_DIR/$slot/ab-version" ]; then
        cat "$BOOT_VERSION_DIR/$slot/ab-version"
        return 0
    fi
    # Otherwise this slot is as the imager wrote it, and the build stamped its
    # own version into the root filesystem.
    [ -r "$VERSION_FILE" ] && cat "$VERSION_FILE" && return 0
    # An image built before this file existed: fall back to something rather
    # than nothing, even though it cannot distinguish two builds of one release.
    ( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}" )
}

health() {
    # systemd's own view. "degraded" means some unit failed, which is exactly
    # the signal a rollout should refuse to call a success -- a machine that
    # boots with its application dead has not been updated, it has been broken.
    case "$(systemctl is-system-running 2>/dev/null)" in
        running|starting) echo ok;;
        "") echo ok;;                      # no systemd: nothing to report on
        *) echo degraded;;
    esac
}

current_slot() { sed -n 's/.*rauc\.slot=\([AB]\).*/\1/p' "$CMDLINE" 2>/dev/null; }
boot_id()      { cat /proc/sys/kernel/random/boot_id 2>/dev/null; }
uptime_secs()  { cut -d. -f1 /proc/uptime 2>/dev/null; }

# ------------------------------------------------------------- update memory
#
# What this machine is in the middle of, remembered across runs and across the
# reboot in the middle of an install. Without it the agent would be handed the
# same bundle on the next beat and install it again, forever.
load_state() { UPDATE_STATE=idle; UPDATE_ROLLOUT=""; UPDATE_ERROR=""; UPDATE_VERSION=""
               # shellcheck source=/dev/null
               [ -r "$STATE" ] && . "$STATE"; return 0; }
save_state() {
    mkdir -p "$STATE_DIR"
    cat > "$STATE" <<EOF
UPDATE_STATE=$UPDATE_STATE
UPDATE_ROLLOUT="$UPDATE_ROLLOUT"
UPDATE_VERSION="$UPDATE_VERSION"
UPDATE_ERROR="$(echo "$UPDATE_ERROR" | tr -d '\n"' | cut -c1-200)"
EOF
}

# ------------------------------------------------------------------ the beat

beat() {
    local id url resp
    id="$(machine_id)"
    [ -n "$id" ] || { log "no usable machine id; not checking in"; return 1; }
    [ -n "$SERVER" ] || { log "no server configured (ab-agent --set-server URL)"; return 1; }

    load_state
    # An install that finished before the last reboot has now been proven or
    # disproven by the version this machine came up on; either way the server
    # decides, and it decides from `version`, so stop claiming to be mid-install.
    if [ "$UPDATE_STATE" = installed ] && [ "$(running_version)" = "$UPDATE_VERSION" ]; then
        UPDATE_STATE=idle; UPDATE_ROLLOUT=""; UPDATE_ERROR=""; save_state
    fi

    url="${SERVER%/}/api/fleet/heartbeat"
    # An array, not ${TOKEN:+-H "..."}: the quotes inside a parameter expansion
    # are not re-evaluated, so that form splits the header on its space and
    # curl is handed "X-Flipside-Agent-Token:" and the token as two arguments,
    # sending neither -- every machine then silently fails to check in.
    #
    # Expanded as ${auth[@]+...} rather than plain "${auth[@]}" because an empty
    # array counts as unset under `set -u` in bash before 4.4, which aborts the
    # script before it ever reaches curl. Debian's bash is newer; the harness
    # and anyone running this on a Mac are not.
    local -a auth=()
    [ -n "$TOKEN" ] && auth=(-H "X-Flipside-Agent-Token: $TOKEN")
    resp="$(curl -fsS --max-time 30 ${auth[@]+"${auth[@]}"} \
                 --data-urlencode "id=$id" \
                 --data-urlencode "hostname=$(hostname 2>/dev/null)" \
                 --data-urlencode "slot=$(current_slot)" \
                 --data-urlencode "version=$(running_version)" \
                 --data-urlencode "boot_id=$(boot_id)" \
                 --data-urlencode "uptime=$(uptime_secs)" \
                 --data-urlencode "health=$(health)" \
                 --data-urlencode "arch=$(uname -m)" \
                 --data-urlencode "agent_version=$AGENT_VERSION" \
                 --data-urlencode "update_state=$UPDATE_STATE" \
                 --data-urlencode "update_rollout=$UPDATE_ROLLOUT" \
                 --data-urlencode "update_error=$UPDATE_ERROR" \
                 "$url" 2>&1)" || {
        # Not an error worth shouting about. A machine that cannot reach the
        # server has usually just moved networks, which is the normal life of a
        # provisioned machine and not a fault. The server notices the silence.
        log "could not reach $url"
        return 1
    }

    # The reply is `key=value` lines, one per line, deliberately not JSON: this
    # runs on a minimal image with no jq and no python3, and adding a JSON
    # parser to every image to read six fields would be a strange trade.
    local action="" bundle_url="" version="" rollout="" advertised="" interval=""
    while IFS='=' read -r key value; do
        case "$key" in
            action)      action="$value";;
            bundle_url)  bundle_url="$value";;
            version)     version="$value";;
            rollout)     rollout="$value";;
            control_url) advertised="$value";;
            interval)    interval="$value";;
            error)       log "server: $value";;
        esac
    done <<EOF
$resp
EOF

    # The server can move the fleet to an address that works from out here. It
    # is the only way to fix a fleet that was imaged pointing at a provisioning
    # address it can no longer reach, short of visiting every machine.
    if [ -n "$advertised" ] && [ "$advertised" != "${SERVER%/}" ]; then
        log "server moved us to $advertised"
        SERVER="$advertised"; save_conf
    fi
    if [ -n "$interval" ] && [ "$interval" != "$INTERVAL" ]; then
        INTERVAL="$interval"; save_conf
    fi

    [ "$action" = update ] || return 0
    [ -n "$bundle_url" ] || { log "server offered an update with no URL"; return 1; }
    apply_update "$bundle_url" "$version" "$rollout"
}

apply_update() {
    local bundle_url="$1" version="$2" rollout="$3"

    if [ "$UPDATE_STATE" = installed ]; then
        log "an update is already installed and waiting for a reboot"
        return 0
    fi

    log "installing $version from $bundle_url (rollout ${rollout:-none})"
    UPDATE_STATE=installing; UPDATE_ROLLOUT="$rollout"; UPDATE_VERSION="$version"
    UPDATE_ERROR=""; save_state
    # Tell the server we started before the long part, not after: an install
    # that takes twenty minutes would otherwise look like a machine that took
    # the offer and vanished, and the rollout would hand the slot to someone
    # else while this one was busy succeeding.
    report_progress

    local out rc
    out="$("$UPDATE_CMD" "$bundle_url" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ]; then
        UPDATE_STATE=failed
        UPDATE_ERROR="$(echo "$out" | grep -iE 'error|failed' | tail -1)"
        [ -n "$UPDATE_ERROR" ] || UPDATE_ERROR="ab-update exited $rc"
        save_state
        log "update failed: $UPDATE_ERROR"
        report_progress
        # The running slot is untouched by a failed install, so this machine is
        # still fine. The rollout is what needs to know, and it now does.
        return 1
    fi

    UPDATE_STATE=installed; save_state
    log "installed $version; the new slot boots on next reboot"
    report_progress

    if [ "$REBOOT" = auto ]; then
        log "rebooting into the new slot"
        # A word to anyone logged in. The rollout's maintenance window decided
        # when this *started*; a long download can carry the reboot past the end
        # of it, which is worth saying out loud rather than hiding.
        wall "Flipside: rebooting into $version in 60 seconds" 2>/dev/null || true
        shutdown -r +1 "Flipside update $version" >/dev/null 2>&1 \
            || { sleep 60; systemctl reboot; }
    else
        log "REBOOT=manual: reboot when ready to finish the update"
    fi
}

report_progress() {
    # Best-effort second beat carrying the new state. Losing it costs nothing:
    # the next scheduled beat carries the same thing, and the server times out
    # an offer it hears nothing about rather than believing it forever.
    [ -n "$SERVER" ] || return 0
    local -a auth=()
    [ -n "$TOKEN" ] && auth=(-H "X-Flipside-Agent-Token: $TOKEN")
    curl -fsS --max-time 15 -o /dev/null ${auth[@]+"${auth[@]}"} \
         --data-urlencode "id=$(machine_id)" \
         --data-urlencode "version=$(running_version)" \
         --data-urlencode "update_state=$UPDATE_STATE" \
         --data-urlencode "update_rollout=$UPDATE_ROLLOUT" \
         --data-urlencode "update_error=$UPDATE_ERROR" \
         "${SERVER%/}/api/fleet/heartbeat" 2>/dev/null || true
}

# ---------------------------------------------------------------------- main

case "${1:-}" in
    -h|--help) sed -n '2,8p' "$0"; exit 0;;
    --set-server)
        [ $# -ge 2 ] || die "--set-server needs a URL"
        case "$2" in http://*|https://*) ;; *) die "the URL must start with http:// or https://";; esac
        SERVER="${2%/}"; save_conf
        echo "Reporting to $SERVER"
        exit 0;;
    --status)
        seed_server; load_state
        echo "server:   ${SERVER:-<not configured>}"
        echo "id:       $(machine_id)"
        echo "hostname: $(hostname 2>/dev/null)"
        echo "slot:     $(current_slot)"
        echo "version:  $(running_version)"
        echo "health:   $(health)"
        echo "update:   $UPDATE_STATE ${UPDATE_ROLLOUT:+(rollout $UPDATE_ROLLOUT)}"
        [ -n "$UPDATE_ERROR" ] && echo "last error: $UPDATE_ERROR"
        exit 0;;
    --now) ENABLED=1;;
    "") ;;
    *) die "unknown option '$1' (try --help)";;
esac

[ "$ENABLED" = 1 ] || { log "agent disabled in $CONF"; exit 0; }
seed_server
# Persist whatever we just worked out, so the next run does not have to derive
# it again -- and so the marker's provisioning address stops being the source of
# truth the moment there is a better answer.
[ -n "$SERVER" ] && [ ! -r "$CONF" ] && save_conf
beat
