#!/bin/sh
# Bind the API to the container network only.
#
# In the single-server layout this container shares the jump host's network
# namespace, so that it can reach managed hosts over the overlay. That namespace
# also holds the tunnel interface every managed host is connected to -- listening on
# 0.0.0.0 there would put the scanner's API in front of the hosts it scans. The
# token is the real control; this keeps the API off the tunnel addresses as well.
set -eu
HOST="${NETSCAN_BIND:-}"
if [ -z "$HOST" ]; then
  DEV=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
  if [ -n "$DEV" ]; then
    HOST=$(ip -4 -o addr show dev "$DEV" | awk '{split($4,a,"/"); print a[1]; exit}')
  fi
fi
if [ -z "$HOST" ]; then
  if [ "${NETSCAN_REQUIRE_OVERLAY:-}" = "1" ]; then
    echo "net-scanner: cannot determine the container-network address to bind to; refusing to listen on every interface" >&2
    exit 1
  fi
  HOST=0.0.0.0
fi
echo "net-scanner: listening on ${HOST}:${NETSCAN_PORT:-8001}"
exec uvicorn app:app --host "$HOST" --port "${NETSCAN_PORT:-8001}"
