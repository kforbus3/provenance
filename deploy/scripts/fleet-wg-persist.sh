#!/bin/sh
# fleet-wg-persist.sh — make a managed host's Fleet WireGuard tunnel survive
# reboots, including when the jump-host endpoint is a DNS name on a dynamic IP.
#
# Run once per managed host as root (it is idempotent):
#     sudo sh fleet-wg-persist.sh            # defaults to interface "wgfleet"
#     sudo sh fleet-wg-persist.sh wg0        # or name the interface
#
# It installs:
#   - a userspace drop-in for wg-quick@<iface> so containers (no kernel WG
#     module) also bring the tunnel up on boot, and enables it on boot;
#   - /usr/local/sbin/fleet-wg-reresolve + a 30s systemd timer that brings the
#     tunnel up if it is down (e.g. DNS wasn't ready at boot) and refreshes the
#     peer endpoint when the handshake goes stale (kernel WG resolves a hostname
#     endpoint only once, so it never recovers on its own otherwise).
set -e
IF="${1:-wgfleet}"
CONF="/etc/wireguard/${IF}.conf"

if [ "$(id -u)" != "0" ]; then echo "run as root" >&2; exit 1; fi
if ! command -v systemctl >/dev/null 2>&1; then echo "systemd required" >&2; exit 1; fi
if [ ! -f "$CONF" ]; then echo "no $CONF — is this host enrolled?" >&2; exit 1; fi

mkdir -p "/etc/systemd/system/wg-quick@${IF}.service.d"
cat > "/etc/systemd/system/wg-quick@${IF}.service.d/fleet.conf" <<'DROPIN'
[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
DROPIN

cat > /usr/local/sbin/fleet-wg-reresolve <<'SCRIPT'
#!/bin/sh
IF="${1:-wgfleet}"
CONF="/etc/wireguard/${IF}.conf"
[ -f "$CONF" ] || exit 0

if [ ! -e "/sys/class/net/${IF}" ]; then
  systemctl start "wg-quick@${IF}" >/dev/null 2>&1 || \
    WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go wg-quick up "$IF" >/dev/null 2>&1 || true
  exit 0
fi

PUB=$(sed -n 's/^PublicKey *= *//p' "$CONF" | head -n1)
EP=$(sed -n 's/^Endpoint *= *//p' "$CONF" | head -n1)
[ -n "$PUB" ] && [ -n "$EP" ] || exit 0

HS=$(wg show "$IF" latest-handshakes 2>/dev/null | awk -v p="$PUB" '$1==p{print $2}')
NOW=$(date +%s)
if [ -z "$HS" ] || [ "$HS" = "0" ] || [ $((NOW - HS)) -gt 150 ]; then
  wg set "$IF" peer "$PUB" endpoint "$EP" >/dev/null 2>&1 || true
fi
SCRIPT
chmod 755 /usr/local/sbin/fleet-wg-reresolve

cat > /etc/systemd/system/fleet-wg-reresolve.service <<UNIT
[Unit]
Description=Fleet WireGuard boot-persistence and endpoint re-resolution
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/fleet-wg-reresolve ${IF}
UNIT

cat > /etc/systemd/system/fleet-wg-reresolve.timer <<'TIMER'
[Unit]
Description=Fleet WireGuard re-resolve timer
[Timer]
OnBootSec=20
OnUnitActiveSec=30
[Install]
WantedBy=timers.target
TIMER

systemctl daemon-reload
systemctl enable "wg-quick@${IF}" >/dev/null 2>&1 || true
systemctl enable --now fleet-wg-reresolve.timer >/dev/null 2>&1 || true
# Bring it current now, too.
/usr/local/sbin/fleet-wg-reresolve "$IF" || true

echo "Installed. wg-quick@${IF} enabled on boot; fleet-wg-reresolve.timer active."
echo "Verify: systemctl is-enabled wg-quick@${IF} ; systemctl status fleet-wg-reresolve.timer"
