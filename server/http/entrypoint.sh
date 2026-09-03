#!/bin/sh
# Render boot.ipxe from environment and expose the imager + images over HTTP.
set -eu

: "${SERVER_IP:?Set SERVER_IP to the IP address of the provisioning server}"
: "${IMAGE_FILE:?Set IMAGE_FILE to the image filename in ./output (e.g. debian-trixie-ab.img.zst)}"
ACTION="${ACTION:-reboot}"

mkdir -p /srv/http /data/hosts
# /data is the mounted ./output directory (images at the root, imager/ inside).
ln -sfn /data        /srv/http/images
ln -sfn /data/imager /srv/http/imager
# Per-machine boot scripts written by the web UI. Created above if absent so a
# missing directory 404s per request rather than breaking nginx at startup.
ln -sfn /data/hosts  /srv/http/hosts
# RAUC update bundles, so a machine can be updated in place instead of
# re-imaged: rauc install http://<server>/bundles/<name>.raucb
mkdir -p /data/bundles 2>/dev/null || true
ln -sfn /data/bundles /srv/http/bundles

# UNASSIGNED decides what a machine with no per-machine assignment gets:
#   image (default) — the default image, i.e. plug in a switch and image it all
#   hold            — discovery: print the MAC, touch nothing, retry
RETRY_SECONDS="${RETRY_SECONDS:-30}"
case "${UNASSIGNED:-image}" in
    hold) FALLBACK="unassigned.ipxe";;
    *)    FALLBACK="default.ipxe";;
esac

# Where the web UI's API lives, for the two endpoints machines report into.
# Both stacks normally run on the same host and this container uses host
# networking, so the loopback address of the UI's published port is right almost
# always. Point it elsewhere when the UI runs on another host.
#
WEBUI_ADDR="${WEBUI_ADDR:-127.0.0.1:8080}"

# Where a machine checks in from once it has left this network. Rendered into
# the default iPXE script as imager.control=, which the imager writes onto the
# machine's BOOT partition for the agent to pick up. Empty renders as an empty
# assignment, which the imager's getarg treats as unset -- so an unconfigured
# server behaves exactly as it did before this existed.
CONTROL_ARG=""
if [ -n "${CONTROL_URL:-}" ]; then
    CONTROL_ARG=" imager.control=${CONTROL_URL%/}"
fi

export SERVER_IP IMAGE_FILE ACTION FALLBACK RETRY_SECONDS WEBUI_ADDR CONTROL_ARG
# boot.ipxe dispatches on MAC and falls back to whichever of the two applies.
envsubst '${SERVER_IP} ${FALLBACK}'                    < /boot.ipxe.tmpl       > /srv/http/boot.ipxe
envsubst '${SERVER_IP} ${IMAGE_FILE} ${ACTION} ${CONTROL_ARG}' < /default.ipxe.tmpl > /srv/http/default.ipxe
envsubst '${RETRY_SECONDS}'                            < /unassigned.ipxe.tmpl > /srv/http/unassigned.ipxe
# Bind the listener to the provisioning IP rather than every host interface.
envsubst '${SERVER_IP} ${WEBUI_ADDR}' < /nginx.conf.tmpl > /etc/nginx/conf.d/default.conf

# nginx resolves a proxy_pass name once, at config load, and refuses to start if
# it cannot -- so a WEBUI_ADDR naming a host that does not resolve would take PXE
# down with it, which is a far worse outcome than losing the progress display.
# Ask nginx itself rather than guessing from the string: a hostname that does
# resolve is perfectly fine and should keep working.
if ! nginx -t >/dev/null 2>&1; then
    echo "WEBUI_ADDR='$WEBUI_ADDR' produces an nginx config that will not load:"
    nginx -t 2>&1 | sed 's/^/  /'
    echo "Falling back to 127.0.0.1:8080. Imaging still works; progress reporting"
    echo "will not reach the web UI unless it is listening there."
    WEBUI_ADDR=127.0.0.1:8080
    export WEBUI_ADDR
    envsubst '${SERVER_IP} ${WEBUI_ADDR}' < /nginx.conf.tmpl > /etc/nginx/conf.d/default.conf
fi

# --- update bundles, reachable from where the fleet actually lives -----------
#
# Optional second listener, off unless UPDATE_IP is set. A machine is on the
# provisioning segment only while it is being imaged; it spends the rest of its
# life on the LAN, which is when it needs updates. Without this, `ab-update`
# from a deployed machine cannot reach anything.
#
# Serves /bundles/ alone -- see nginx-updates.conf.tmpl for why that is safe and
# a wider bind is not. Use the host's LAN address, or 0.0.0.0 to accept on every
# interface as an explicit choice rather than a side effect.
rm -f /etc/nginx/conf.d/updates.conf
if [ -n "${UPDATE_IP:-}" ]; then
    UPDATE_PORT="${UPDATE_PORT:-80}"
    # Two default_servers on one address:port is a startup failure, and nginx
    # failing to start takes PXE down with it -- so a UPDATE_IP that collides
    # with the imaging listener is a no-op with a note, not an outage. The
    # imaging listener already serves /bundles/ on that socket anyway.
    if [ "$UPDATE_IP" = "$SERVER_IP" ] && [ "$UPDATE_PORT" = "80" ]; then
        echo "UPDATE_IP is SERVER_IP on port 80; the imaging listener already serves"
        echo "/bundles/ there. Not adding a second listener."
    else
        export UPDATE_IP UPDATE_PORT
        envsubst '${UPDATE_IP} ${UPDATE_PORT} ${WEBUI_ADDR}' < /nginx-updates.conf.tmpl \
            > /etc/nginx/conf.d/updates.conf
        echo "Update bundles also served on ${UPDATE_IP}:${UPDATE_PORT}/bundles/"
    fi
fi

echo "----- rendered /srv/http/boot.ipxe -----"
cat /srv/http/boot.ipxe
echo "----------------------------------------"

exec nginx -g 'daemon off;'
