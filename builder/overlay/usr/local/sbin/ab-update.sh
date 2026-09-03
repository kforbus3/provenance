#!/bin/bash
# Update this machine in place, using the slot it is not running on.
#
#   ab-update                              # newest bundle from the server it was imaged from
#   ab-update http://host/bundles/x.raucb  # a specific bundle
#   ab-update --status                     # which slot is running, and what is on the other
#
# This is what the two root slots are for. The update is written to the inactive
# slot while this one keeps running, the boot order flips, and the machine
# reboots into it. If it fails to come up, GRUB's try-counter falls back to the
# slot you are on now, which is untouched.
#
# The overlay is not part of the update: /home, /etc and everything else written
# since imaging live there and are deliberately carried across. Run
# ab-overlay-diff afterwards if a file from the new image seems not to have
# arrived -- an old copy in the overlay shadows it (see docs/RECOVERY.md).
set -u

MARKER=/boot/ab-deploy.json

usage() { sed -n '2,18p' "$0"; exit 0; }

case "${1:-}" in
    -h|--help) usage;;
    --status)
        rauc status 2>/dev/null || echo "rauc is not available on this system"
        exit $?;;
esac

BUNDLE="${1:-}"

if [ -z "$BUNDLE" ]; then
    # No URL given: ask the server this machine was imaged from. The address is
    # the one the imager left behind, which is the only thing here that knows it.
    [ -r "$MARKER" ] || {
        echo "No bundle URL given, and $MARKER does not exist so there is no server" >&2
        echo "to ask. Pass a URL: ab-update http://<server>/bundles/<name>.raucb" >&2
        exit 2
    }
    base="$(sed -n 's|.*"checkin_url"[[:space:]]*:[[:space:]]*"\(https\?://[^/]*\)/.*|\1|p' "$MARKER")"
    [ -n "$base" ] || { echo "could not read the server address from $MARKER" >&2; exit 2; }

    echo "Looking for the newest bundle on ${base}"
    # nginx autoindex is not enabled, so the listing is not something to parse.
    # The server publishes a small pointer file instead; without it, be explicit
    # rather than guessing at a filename.
    BUNDLE="$(curl -fsS --max-time 15 "${base}/bundles/latest" 2>/dev/null | tr -d '\r\n')"
    [ -n "$BUNDLE" ] || {
        echo "No 'latest' pointer published at ${base}/bundles/latest." >&2
        echo "Create a bundle in the web UI, or pass the URL directly." >&2
        exit 3
    }
    case "$BUNDLE" in
        http://*|https://*) ;;
        *) BUNDLE="${base}/bundles/${BUNDLE}";;
    esac
fi

echo "Installing $BUNDLE"
echo "This writes the inactive slot; the running system is not touched."

LOG="$(mktemp /tmp/ab-update.XXXXXX)"
trap 'rm -f "$LOG"' EXIT

# --- is this a bundle at all? ------------------------------------------------
#
# A RAUC bundle is a squashfs, so it starts with the four bytes "hsqs". Checking
# them costs one range request and catches the mistake that is otherwise
# unreadable: a URL answered by something that is not the bundle server. Pointed
# at the web UI's port, whose SPA returns index.html for any unknown path, RAUC
# streamed the React app and reported
#
#   Invalid bundle format: Signature size (4336799815442382346) exceeds bundle size
#
# because it read the last eight bytes of an HTML page -- "</html>\n" -- as the
# signature size. Nothing in that says "wrong port", and the old advice under it
# sent people to check a signing key instead.
#
# Three outcomes, not two. A server that will not do range requests, a missing
# curl, or an unreadable file means this check cannot answer -- and "cannot
# tell" must never block an update that would have worked. Only a definite
# answer stops anything.
#
#   0 = starts with the squashfs magic     2 = could not tell, carry on
#   1 = definitely something else
looks_like_bundle() {  # $1 = url or local path
    _magic=""
    case "$1" in
        http://*|https://*)
            command -v curl >/dev/null || return 2
            _magic="$(curl -fsS --max-time 20 -r 0-3 "$1" 2>/dev/null | head -c 4)";;
        *)  _magic="$(head -c 4 "$1" 2>/dev/null)";;
    esac
    [ -n "$_magic" ] || return 2
    [ "$_magic" = "hsqs" ] || return 1
    return 0
}

looks_like_bundle "$BUNDLE"
if [ "$?" = 1 ]; then
    {
        echo ""
        echo "$BUNDLE"
        echo "does not start with a squashfs magic, so it is not a RAUC bundle."
        echo "Nothing was installed and this machine is untouched."
        echo ""
        case "$BUNDLE" in
            *:8080/*)
                echo "  Port 8080 is the web UI, which answers any unknown path with its"
                echo "  own front page. Bundles are served by the provisioning server:"
                echo "  drop the port, or use 'ab-update' with no arguments.";;
            *)
                echo "  Check the URL. A web server that answers an unknown path with an"
                echo "  error page rather than a 404 produces exactly this.";;
        esac
    } >&2
    exit 4
fi

install_bundle() {
    rauc install "$1" 2>&1 | tee "$LOG"
    return "${PIPESTATUS[0]}"
}

rc=0
install_bundle "$BUNDLE" || rc=$?

# --- fall back to downloading, whatever went wrong while streaming ------------
#
# RAUC installs from a URL by streaming: an NBD device backed by HTTP range
# requests, with dm-verity over it. That saves having to land the bundle on
# disk first, and it has a lot of moving parts -- the server has to handle
# ranges and report a size, the connection has to survive hundreds of requests,
# and the kernel has to bring up nbd and dm-verity together. Downloading first
# turns all of that into an ordinary local install.
#
# This used to retry only on "not supported in streaming mode", the one failure
# a 'plain' bundle produces. Every other way streaming can fail went straight to
# "update failed" with the bundle sitting there, perfectly installable, one curl
# away. That is how the nightly test failed for a week: the bundle streamed onto
# an nbd device that was torn down before dm-verity was set up, RAUC reported
# "Hash device is too small", no retry fired, and the run stopped.
#
# So: any failure of a streamed install is worth one local retry. The bundle is
# verified against the keyring either way -- downloading changes how the bytes
# arrive, not whether they are trusted -- so this trades disk space for a
# working update, and never trust for convenience.
if [ "$rc" -ne 0 ]; then
    case "$BUNDLE" in
        http://*|https://*)
            tmp="/var/tmp/$(basename "$BUNDLE")"
            echo ""
            echo "Streaming the update failed. Downloading the bundle and installing"
            echo "it from disk instead, which avoids streaming entirely."
            # A partial download is indistinguishable from a whole one to
            # everything except RAUC's signature check, and the failure it
            # produces there looks like a bad key rather than a short file. Say
            # up front when there is not enough room.
            need="$(curl -fsSLI --max-time 20 "$BUNDLE" 2>/dev/null \
                    | awk 'tolower($1) ~ /^content-length:/ {print $2+0}' | tail -1)"
            free="$(df -kP /var/tmp 2>/dev/null | awk 'NR==2 {print $4 * 1024}')"
            if [ -n "${need:-}" ] && [ -n "${free:-}" ] && [ "$need" -gt 0 ] \
               && [ "$free" -lt "$need" ]; then
                echo "Not enough room in /var/tmp: the bundle needs $((need / 1048576)) MiB" >&2
                echo "  and $((free / 1048576)) MiB is free. Free some space and retry." >&2
            elif curl -fL --progress-bar -o "$tmp" "$BUNDLE"; then
                # The streamed attempt checked four bytes from a range request;
                # this checks what actually landed. A redirect to a login page
                # or an error document downloads with exit 0 and the right name.
                looks_like_bundle "$tmp"
                if [ "$?" = 1 ]; then
                    echo "What downloaded is not a RAUC bundle. Nothing was installed." >&2
                    rm -f "$tmp"
                    exit 4
                fi
                rc=0
                install_bundle "$tmp" || rc=$?
                rm -f "$tmp"
            else
                echo "Downloading the bundle failed as well." >&2
                rm -f "$tmp"
            fi
            ;;
    esac
fi

# Report what actually went wrong, rather than a list of things that might.
#
# This printed the signing-key and compatible hints on every failure regardless
# of the error, so a dm-verity failure came with a confident explanation about
# certificates. A wrong diagnosis costs more than none: it sends whoever is
# reading it to check a key that was never the problem. Each hint is now tied to
# the error that actually implies it, and the real message from RAUC is quoted
# either way.
if [ "$rc" -ne 0 ]; then
    {
        echo ""
        echo "Update failed (rauc exit $rc). The running slot is unchanged, so this"
        echo "machine is still bootable."
        echo ""
        echo "What RAUC reported:"
        grep -iE "LastError|failed|error" "$LOG" 2>/dev/null | tail -3 | sed 's/^/  /'
        echo ""
        if grep -qiE "signature|keyring|certificate|verif" "$LOG" 2>/dev/null; then
            echo "  This looks like a trust problem: the bundle is signed by a key this"
            echo "  image does not carry. The certificate has to be inside the image when"
            echo "  it is built -- rebuild the image against the signing cert, not the"
            echo "  bundle."
        fi
        if grep -qi "compatible" "$LOG" 2>/dev/null; then
            echo "  This machine's compatible is '$(sed -n 's/^compatible=//p' /etc/rauc/system.conf 2>/dev/null)';"
            echo "  the bundle must declare the same one."
        fi
        if grep -qiE "dm table|verity|nbd|mounting bundle|streaming" "$LOG" 2>/dev/null; then
            echo "  This is a streaming problem, not a problem with the bundle. The"
            echo "  download-and-install retry above should have avoided it; if that"
            echo "  also failed, check free space in /var/tmp and that the server"
            echo "  serves the whole file."
        fi
    } >&2
    exit "$rc"
fi

# Belt and braces. RAUC's post-install handler has already done this, and it is
# the one that also covers `rauc install` run by hand -- but a handler that did
# not run leaves the new slot booting with no fallback at all, and that is not
# something to discover by needing it. Setting it twice costs one grubenv write
# and is idempotent.
if [ -x /usr/local/sbin/ab-slot-pending.sh ]; then
    /usr/local/sbin/ab-slot-pending.sh || true
fi

echo ""
echo "Installed. Reboot to switch slots:  systemctl reboot"
echo "If the new slot fails to boot, GRUB falls back to this one automatically."
