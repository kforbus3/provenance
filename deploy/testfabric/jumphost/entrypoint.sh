#!/bin/sh
# Fleet Terminal test fabric — jump host entrypoint.
#
# Brings up the WireGuard hub (wg0) with a stable keypair, then starts sshd.
# Prefers the kernel WireGuard module (faster) and falls back to userspace
# wireguard-go when the module is unavailable (e.g. macOS Docker Desktop, or a
# Linux host that has not loaded the wireguard module). Managed-host *peers are
# NOT configured here* — the Fleet Terminal enrollment flow adds each peer
# dynamically (wg set) when a host is enrolled.
set -e

WG_IFACE="${WG_INTERFACE:-wg0}"
WG_PORT="${WG_PORT:-51820}"
WG_ADDR="${WG_ADDRESS:-10.100.0.1/24}"

mkdir -p /etc/wireguard /run/sshd
umask 077

# Generate a persistent keypair on first boot; the backend reads the public key
# over SSH (/etc/wireguard/publickey) during enrollment.
if [ ! -f /etc/wireguard/privatekey ]; then
  wg genkey > /etc/wireguard/privatekey
  wg pubkey < /etc/wireguard/privatekey > /etc/wireguard/publickey
fi

# Create the hub interface. Prefer the kernel module; the interface is then
# configured identically (wg set + ip) whether it is kernel- or userspace-backed.
# A stale interface from a previous run (if the netns is reused) is cleared first.
ip link del "$WG_IFACE" >/dev/null 2>&1 || true
if ip link add dev "$WG_IFACE" type wireguard >/dev/null 2>&1; then
  echo "[jumphost] using kernel WireGuard hub on ${WG_IFACE}"
else
  echo "[jumphost] kernel module unavailable; starting userspace wireguard-go hub on ${WG_IFACE}"
  wireguard-go "$WG_IFACE"
  # Wait for the userspace control socket to appear before configuring.
  i=0
  while [ "$i" -lt 15 ]; do
    if wg show "$WG_IFACE" >/dev/null 2>&1; then break; fi
    i=$((i + 1)); sleep 1
  done
fi

wg set "$WG_IFACE" listen-port "$WG_PORT" private-key /etc/wireguard/privatekey
ip address add "$WG_ADDR" dev "$WG_IFACE" 2>/dev/null || true
ip link set "$WG_IFACE" up

# Re-apply persisted peers. Enrollment writes each managed host to
# /etc/wireguard/peers/<host>.conf; runtime `wg set` peers are otherwise lost on
# restart. When /etc/wireguard is on a volume (production), this keeps every
# enrolled host reachable across jump-host restarts/upgrades — no re-enrollment.
if [ -d /etc/wireguard/peers ]; then
  for f in /etc/wireguard/peers/*.conf; do
    [ -f "$f" ] || continue
    wg addconf "$WG_IFACE" "$f" 2>/dev/null && echo "[jumphost] restored peer from $(basename "$f")"
  done
fi
echo "[jumphost] wg0 up at ${WG_ADDR}; peers added on demand by enrollment"

# Auto-trust the Fleet CA. When FLEET_BACKEND_URL is set (production single-server
# deployment), poll the backend's public CA endpoint and keep
# /etc/ssh/fleet_ca.pub current — this self-establishes trust on first boot and
# tracks CA rotation, with no manual `make trust` step. In the local test fabric
# FLEET_BACKEND_URL is unset and trust is seeded by `make trust` instead.
if [ -n "${FLEET_BACKEND_URL:-}" ]; then
  echo "[jumphost] CA auto-sync enabled from ${FLEET_BACKEND_URL}"
  (
    interval="${FLEET_CA_SYNC_INTERVAL:-300}"
    while true; do
      if curl -fsS --max-time 10 "${FLEET_BACKEND_URL%/}/api/v1/certificates/ca/pub" -o /tmp/fleet_ca.new 2>/dev/null \
         && [ -s /tmp/fleet_ca.new ]; then
        if ! cmp -s /tmp/fleet_ca.new /etc/ssh/fleet_ca.pub; then
          cp /tmp/fleet_ca.new /etc/ssh/fleet_ca.pub
          chmod 644 /etc/ssh/fleet_ca.pub
          pkill -HUP sshd 2>/dev/null || true
          echo "[jumphost] installed/updated Fleet CA trust"
        fi
      fi
      sleep "$interval"
    done
  ) &
fi

# Ensure host keys exist, then run sshd in the foreground. The ed25519 key lives
# under /etc/ssh/keys (persisted on a volume in production) so the jump host's
# identity is stable for known_hosts pinning; default keys cover other types.
mkdir -p /etc/ssh/keys
[ -f /etc/ssh/keys/ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/keys/ssh_host_ed25519_key
ssh-keygen -A >/dev/null 2>&1 || true
echo "[jumphost] starting sshd"
exec /usr/sbin/sshd -D -e
