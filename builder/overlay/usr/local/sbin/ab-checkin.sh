#!/bin/bash
# Tell the provisioning server this machine booted the image it was given.
#
# The imager's last report is sent before the reboot, so without this a machine
# that images perfectly and then fails to boot is indistinguishable from one
# that worked. This is the other half of that: the machine itself says it came
# up, and what it came up as.
#
# The server address is not known to the running system -- by then there is no
# kernel command line pointing at it -- so the imager leaves it on the BOOT
# partition, which is plain ext4 and mounted at /boot here.
#
# Deliberately best-effort and quiet. A machine that cannot reach the server (a
# different network by now, which is the normal case for a provisioned machine)
# is not broken, and must not boot any slower or log an error for it.
set -u

MARKER=/boot/ab-deploy.json
[ -r "$MARKER" ] || exit 0

url="$(sed -n 's/.*"checkin_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$MARKER")"
[ -n "$url" ] || exit 0

# The identity the imager reported under, so the server can join the two events
# into one machine rather than inventing a second.
id="$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$MARKER")"
if [ -z "$id" ]; then
    for f in /sys/class/net/*/address; do
        a="$(cat "$f" 2>/dev/null)"
        case "$a" in ""|00:00:00:00:00:00) continue;; esac
        case "$f" in */lo/*) continue;; esac
        id="$a"; break
    done
fi
[ -n "$id" ] || exit 0

slot="$(sed -n 's/.*rauc\.slot=\([AB]\).*/\1/p' /proc/cmdline 2>/dev/null)"
version="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-}")"

curl -fsS --max-time 10 -o /dev/null \
     --data-urlencode "id=${id}" \
     --data-urlencode "hostname=$(hostname 2>/dev/null)" \
     --data-urlencode "slot=${slot}" \
     --data-urlencode "version=${version}" \
     "$url" 2>/dev/null || exit 0
