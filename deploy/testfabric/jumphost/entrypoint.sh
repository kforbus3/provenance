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

# Peer isolation: make the overlay strict hub-and-spoke. A managed host's own
# config carries AllowedIPs = <the whole overlay subnet>, so its packets for a
# SIBLING host are encrypted to the hub and would be forwarded straight back out
# the same interface — giving any compromised host direct L3 reach to every other
# host's sshd/RDP/WinRM port, bypassing the brokering, RBAC and session audit that
# is the entire point of Fleet. Drop those forwards.
#
# This costs nothing operationally: every path Fleet uses (terminal, SFTP, the
# monitor probes, ansible via ProxyJump, the DB/Kubernetes brokers) is dialed
# FROM this jump host, so it leaves via OUTPUT and is never a forwarded flow.
#
# Two independent rules, either of which is sufficient on its own:
#   1. interface-scoped — covers the WireGuard hub;
#   2. subnet-scoped    — the same deny expressed on the WireGuard subnet.
# The OpenVPN overlay has its OWN subnet (it must: two overlays sharing one subnet
# on this host would give it two routes for one prefix). Its intra-subnet deny is
# installed by enrollment when the server is provisioned; what only this script can
# add is the CROSS-overlay deny, since a host on one transport reaching a host on the
# other is a forwarded flow between two different interfaces that neither overlay's
# own rule matches.
# ip_forward stays on: the jump host may legitimately route elsewhere, and the
# narrow rules say what we actually mean.
#
# Failure here is loud but non-fatal — some kernels/hosts give the container no
# usable iptables backend, and a jump host that cannot filter is still a working
# jump host. Set FLEET_OVERLAY_PEER_ISOLATION=0 for a deployment that genuinely
# needs managed hosts to reach each other over the overlay.
if [ "${FLEET_OVERLAY_PEER_ISOLATION:-1}" = "1" ]; then
  # The connected route the kernel installed for WG_ADDR is the overlay subnet,
  # already in network form (10.100.0.1/24 -> 10.100.0.0/24) — no CIDR maths.
  WG_SUBNET=$(ip -4 route show dev "$WG_IFACE" 2>/dev/null | awk '$1 ~ /\// {print $1; exit}')
  applied=""
  # -C tests for an existing identical rule, so a restart re-applying this (or the
  # enrollment flow adding it too) cannot stack duplicates. Insert at the head
  # rather than append: a deny this fundamental must not sit behind an ACCEPT an
  # operator added earlier in the chain.
  if iptables -C FORWARD -i "$WG_IFACE" -o "$WG_IFACE" -j DROP >/dev/null 2>&1 \
     || iptables -I FORWARD 1 -i "$WG_IFACE" -o "$WG_IFACE" -j DROP >/dev/null 2>&1; then
    applied="$WG_IFACE"
  fi
  if [ -n "$WG_SUBNET" ]; then
    if iptables -C FORWARD -s "$WG_SUBNET" -d "$WG_SUBNET" -j DROP >/dev/null 2>&1 \
       || iptables -I FORWARD 1 -s "$WG_SUBNET" -d "$WG_SUBNET" -j DROP >/dev/null 2>&1; then
      applied="${applied:+$applied, }$WG_SUBNET"
    fi
  fi
  # Cross-overlay: a managed host on WireGuard must not reach one on OpenVPN, or the
  # reverse. Each overlay's own rule only covers traffic that stays inside it, so
  # without this a two-transport deployment has a hole exactly where the fleet is
  # mixed. Skipped when the two subnets are the same (a single-overlay deployment),
  # where the intra-subnet rule above already covers it.
  OVPN_SUBNET="${FLEET_OVPN_SUBNET:-10.101.0.0/24}"
  if [ -n "$WG_SUBNET" ] && [ "$OVPN_SUBNET" != "$WG_SUBNET" ]; then
    for pair in "$WG_SUBNET $OVPN_SUBNET" "$OVPN_SUBNET $WG_SUBNET"; do
      set -- $pair
      if iptables -C FORWARD -s "$1" -d "$2" -j DROP >/dev/null 2>&1 \
         || iptables -I FORWARD 1 -s "$1" -d "$2" -j DROP >/dev/null 2>&1; then
        applied="${applied:+$applied, }$1->$2"
      fi
    done
  fi
  # Report what actually went in, not what was attempted: either rule alone
  # isolates the WireGuard hub, so a partial apply is still ON — but an operator
  # reading this needs to know which one is carrying it.
  if [ -n "$applied" ]; then
    echo "[jumphost] overlay peer isolation ON (managed hosts cannot reach each other; enforced on $applied)"
  else
    echo "[jumphost] WARN could not apply overlay peer isolation (no usable iptables backend?); managed hosts CAN reach each other over the overlay"
  fi
else
  echo "[jumphost] WARN overlay peer isolation DISABLED by FLEET_OVERLAY_PEER_ISOLATION; managed hosts can reach each other over the overlay"
fi

# Re-apply persisted peers. Enrollment writes each managed host to
# /etc/wireguard/peers/<host>.conf; runtime `wg set` peers are otherwise lost on
# restart. When /etc/wireguard is on a volume (production), this keeps every
# enrolled host reachable across jump-host restarts/upgrades — no re-enrollment.
if [ -d /etc/wireguard/peers ]; then
  claimed=""
  for f in /etc/wireguard/peers/*.conf; do
    [ -f "$f" ] || continue
    # Guard against duplicate AllowedIPs claims: in WireGuard the LAST peer
    # assigned an allowed-ip silently steals it from an earlier one, so a stale
    # fragment (leftover from a deleted host whose overlay IP was reused) would
    # dead-end the live host's tunnel. First file wins; later claimants are
    # skipped loudly so the operator can delete the stale fragment.
    ips=$(sed -n 's/^[[:space:]]*AllowedIPs[[:space:]]*=[[:space:]]*//p' "$f" | head -1)
    if [ -n "$ips" ] && printf '%s' "$claimed" | grep -qFx "$ips"; then
      echo "[jumphost] WARN skipping $(basename "$f"): AllowedIPs $ips already claimed by an earlier peer file (stale leftover from a removed host? delete it)"
      continue
    fi
    # Keep the peer's Endpoint so the hub can initiate to the host immediately,
    # instead of sitting mute until the host happens to call in. A host whose own
    # configured Endpoint is unreachable is carried entirely by the hub calling it;
    # dropping the endpoint here strands such a host permanently, and the symptom
    # (two hosts offline after an unrelated redeploy, everything else fine) points
    # nowhere near this line.
    #
    # The endpoint is dropped ONLY when it will not resolve: `wg addconf` fails the
    # whole peer on an unresolvable endpoint, and a member host may legitimately be
    # offline or DNS may not be answering this early in boot. Losing the endpoint is
    # survivable (the host can still call in and the hub relearns it via roaming);
    # losing the peer is not.
    ep=$(sed -n 's/^[[:space:]]*Endpoint[[:space:]]*=[[:space:]]*//p' "$f" | head -1)
    ephost=$(printf '%s' "${ep%:*}" | tr -d '[]')   # strip :port and IPv6 brackets
    keep_ep=yes
    case "$ephost" in
      "") ;;                                         # no endpoint recorded
      *[!0-9.]*)                                     # not a bare IPv4 literal
        case "$ephost" in
          *:*) ;;                                    # IPv6 literal — no lookup needed
          *) getent hosts "$ephost" >/dev/null 2>&1 || keep_ep=no ;;
        esac ;;
    esac
    tmp=$(mktemp)
    if [ "$keep_ep" = no ]; then
      echo "[jumphost] WARN $(basename "$f"): endpoint '$ep' does not resolve; restoring peer without it (the hub cannot initiate to this host until it calls in)"
      grep -vi '^[[:space:]]*Endpoint' "$f" > "$tmp"
    else
      cat "$f" > "$tmp"
    fi
    if wg addconf "$WG_IFACE" "$tmp" 2>/dev/null; then
      echo "[jumphost] restored peer from $(basename "$f")"
      if [ -n "$ips" ]; then claimed="${claimed}${ips}
"; fi
    else
      echo "[jumphost] WARN could not restore peer from $(basename "$f")"
    fi
    rm -f "$tmp"
  done
fi
echo "[jumphost] wg0 up at ${WG_ADDR}; peers added on demand by enrollment"

# Restart the OpenVPN overlay server if one has been provisioned. Enrollment starts
# it once, as a daemon inside this container; nothing else brings it back. WireGuard
# survives a restart because its peers are restored above from a volume — the cert
# overlay needs the same treatment or every upgrade silently drops every host that
# uses it, with the hosts' own clients retrying into a closed port.
#
# Requires /etc/openvpn/fleet to be on a volume (see docker-compose.jumphost.yml);
# without one the material is gone with the old container and this is a no-op.
if [ -f /etc/openvpn/fleet/server.conf ] && command -v openvpn >/dev/null 2>&1; then
  # Match on process NAME, then confirm the config from /proc: `pgrep -f` would also
  # match this script, whose own text contains the command line below.
  ovpn_running() {
    for _p in $(pgrep -x openvpn 2>/dev/null); do
      if tr '\0' ' ' < "/proc/$_p/cmdline" 2>/dev/null | grep -qF -- '/etc/openvpn/fleet/server.conf'; then return 0; fi
    done
    return 1
  }
  if ovpn_running; then
    echo "[jumphost] openvpn overlay server already running"
  elif openvpn --config /etc/openvpn/fleet/server.conf --daemon fleet-overlay \
        --writepid /run/fleet-ovpn.pid --log-append /etc/openvpn/fleet/server.log; then
    sleep 1
    if ovpn_running; then
      echo "[jumphost] openvpn overlay server restarted"
    else
      echo "[jumphost] WARN openvpn overlay server failed to start; see /etc/openvpn/fleet/server.log"
    fi
  else
    echo "[jumphost] WARN could not launch the openvpn overlay server"
  fi
fi

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
