// Package overlay generates the FIPS OpenVPN overlay's server, client, and per-host
// configuration. It is the parallel sibling of the WireGuard enrollment path
// (internal/enrollment): selected only when FLEET_OVERLAY=openvpn, so the default
// WireGuard overlay is completely untouched.
//
// The overlay has its own subnet/jump-IP (FLEET_OVPN_SUBNET) but reuses the
// hosts.wg_address column for a host's assigned address, so the SSH gateway's address
// resolution needs no changes — a host is dialed at its overlay address whichever
// overlay assigned it. All configs here are the exact shape validated end-to-end
// against a real OpenVPN 2.6 / OpenSSL 3 server+client (ECDSA P-256 certs, TLS 1.2+,
// AES-256-GCM, ECDHE P-256 via tls-groups — no X25519).
package overlay

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/overlaypki"
)

// clientCertTTL is a managed host's OpenVPN client-cert lifetime. Long-lived (the
// overlay is persistent); rotation is a future migration step.
const clientCertTTL = 2 * 365 * 24 * time.Hour

// fleetDir is where overlay material lives on both the jump host and managed hosts.
const fleetDir = "/etc/openvpn/fleet"

// OpenVPN builds the OpenVPN overlay's configuration from Fleet's settings + PKI.
type OpenVPN struct {
	cfg *config.Config
	pki *overlaypki.PKI
}

func New(cfg *config.Config, pki *overlaypki.PKI) *OpenVPN {
	return &OpenVPN{cfg: cfg, pki: pki}
}

// subnetParts splits the OpenVPN overlay's own subnet ("10.101.0.0/24") into
// network + dotted netmask for the `server` directive and ccd `ifconfig-push`.
//
// This is deliberately NOT the WireGuard subnet. Both overlays terminate on the same
// jump host and each claims its jump address on its own interface, so sharing a
// subnet gives that host two connected routes for one prefix — resolved once by the
// kernel, for the whole prefix — and strands every host behind the losing interface.
func (o *OpenVPN) subnetParts() (network, netmask string, err error) {
	_, ipnet, err := net.ParseCIDR(o.cfg.OVPNSubnet)
	if err != nil {
		return "", "", fmt.Errorf("bad FLEET_OVPN_SUBNET %q: %w", o.cfg.OVPNSubnet, err)
	}
	mask := ipnet.Mask
	if len(mask) != net.IPv4len {
		return "", "", fmt.Errorf("overlay subnet must be IPv4")
	}
	return ipnet.IP.String(), fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]), nil
}

// Netmask returns the overlay subnet's dotted netmask (for ccd entries).
func (o *OpenVPN) Netmask() (string, error) {
	_, mask, err := o.subnetParts()
	return mask, err
}

// ServerConfig returns the jump-host OpenVPN server.conf. The server takes the
// first host of the subnet (OVPNJumpIP) as its own tun address and pins static
// per-host IPs from client-config-dir.
func (o *OpenVPN) ServerConfig() (string, error) {
	network, netmask, err := o.subnetParts()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`# Fleet OpenVPN overlay — jump-host server (FIPS). Managed by Fleet; do not edit.
dev tun
proto udp
port %d
ca %s/ca.crt
cert %s/server.crt
key %s/server.key
dh none
tls-server
tls-version-min 1.2
tls-groups secp256r1:secp384r1
data-ciphers AES-256-GCM
data-ciphers-fallback AES-256-GCM
server %s %s
topology subnet
client-config-dir %s/ccd
keepalive 10 60
persist-key
persist-tun
verb 3
`, o.cfg.OVPNPort, fleetDir, fleetDir, fleetDir, network, netmask, fleetDir), nil
}

// ClientConfig returns a managed host's client.ovpn (references the cert/key/ca
// files the install script writes next to it). Any port on `endpoint` is ignored —
// the overlay always dials the configured OVPNPort, never the WireGuard endpoint's.
func (o *OpenVPN) ClientConfig(endpoint string) string {
	host := endpoint
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		host = h
	}
	port := o.cfg.OVPNPort
	return fmt.Sprintf(`# Fleet OpenVPN overlay — managed-host client (FIPS). Managed by Fleet; do not edit.
dev tun
proto udp
client
nobind
remote %s %d
ca %s/ca.crt
cert %s/client.crt
key %s/client.key
remote-cert-tls server
tls-version-min 1.2
tls-groups secp256r1:secp384r1
data-ciphers AES-256-GCM
data-ciphers-fallback AES-256-GCM
persist-key
persist-tun
keepalive 10 60
verb 3
%s`, host, port, fleetDir, fleetDir, fleetDir, o.clientIsolationDirectives())
}

// clientIsolationDirectives hooks the host-side peer-isolation script into the
// client config, or returns "" when isolation is off.
//
// This is OpenVPN's stand-in for WireGuard's AllowedIPs. A WireGuard peer entry is
// simultaneously a route table and an inbound source filter, so pinning it to the
// jump host isolates the host at its own end. OpenVPN has no equivalent: a client
// accepts whatever arrives down the tunnel. Without this, an OpenVPN deployment's
// isolation rests entirely on one iptables rule on the jump host — which fails open
// by design, and on a jump host Fleet does not own may never be applied at all.
//
// It runs on `up` rather than being written once at install because that is what
// makes it survive a reboot (a plain iptables rule does not) and what gives it the
// tunnel's actual device name, which OpenVPN assigns at runtime.
func (o *OpenVPN) clientIsolationDirectives() string {
	if !o.cfg.OverlayPeerIsolation {
		return ""
	}
	// script-security 2 is the minimum that lets OpenVPN run a user script. The
	// script is root-owned, 0700, and written by Fleet.
	return fmt.Sprintf("script-security 2\nup %s/peer-isolation.sh\n", fleetDir)
}

// hostIsolationScript renders the managed host's `up` script: everything arriving on
// or leaving via the tunnel that is not the jump host is dropped.
//
// The rules are scoped to $dev (the tun device OpenVPN just brought up) rather than
// to the overlay subnet. That matters — a subnet-scoped rule would also match the
// host talking to its OWN overlay address over loopback, breaking any local service
// bound to it. Interface-scoped rules leave loopback alone and need no knowledge of
// the device number.
//
// It always exits 0. With script-security 2 a failing `up` script aborts the tunnel,
// and a host that cannot filter is still a host Fleet must be able to reach — so this
// fails open like every other half of peer isolation, loudly, in the OpenVPN log.
func (o *OpenVPN) hostIsolationScript() string {
	if !o.cfg.OverlayPeerIsolation {
		return ""
	}
	jump := strings.TrimSpace(o.cfg.OVPNJumpIP)
	if net.ParseIP(jump) == nil {
		return ""
	}
	return fmt.Sprintf(`#!/bin/sh
# Fleet overlay peer isolation — managed-host side. Managed by Fleet; do not edit.
# OpenVPN runs this as the tunnel comes up, with $dev set to the tun device.
JUMP=%s
[ -n "$dev" ] || { echo "fleet: no \$dev; peer isolation NOT applied" >&2; exit 0; }
if ! command -v iptables >/dev/null 2>&1; then
  echo "fleet: iptables unavailable; peer isolation NOT applied" >&2; exit 0
fi
# The rules live in Fleet's own chains, flushed and refilled on every run. Inserting
# them directly into INPUT/OUTPUT was idempotent but not self-correcting: the rule
# names the jump host by address, so changing it (as moving the overlay onto its own
# subnet did) left the previous DROP in place, matching everything from the NEW jump
# host and blackholing the tunnel with no error anywhere. Flushing a chain we own
# removes the stale rule as a side effect of writing the current one.
for _c in FLEET-OVPN-IN FLEET-OVPN-OUT; do
  iptables -N "$_c" 2>/dev/null
  iptables -F "$_c" 2>/dev/null
done
# -C before -I on the jumps into those chains: this runs on every reconnect and must
# not stack duplicates.
iptables -C INPUT  -i "$dev" -j FLEET-OVPN-IN 2>/dev/null || \
  iptables -I INPUT  1 -i "$dev" -j FLEET-OVPN-IN 2>/dev/null || \
  echo "fleet: could not hook inbound peer isolation on $dev" >&2
iptables -C OUTPUT -o "$dev" -j FLEET-OVPN-OUT 2>/dev/null || \
  iptables -I OUTPUT 1 -o "$dev" -j FLEET-OVPN-OUT 2>/dev/null || \
  echo "fleet: could not hook outbound peer isolation on $dev" >&2
iptables -A FLEET-OVPN-IN  ! -s "$JUMP"/32 -j DROP 2>/dev/null || \
  echo "fleet: could not apply inbound peer isolation on $dev" >&2
iptables -A FLEET-OVPN-OUT ! -d "$JUMP"/32 -j DROP 2>/dev/null || \
  echo "fleet: could not apply outbound peer isolation on $dev" >&2
exit 0
`, jump)
}

// CCDEntry pins a client (by cert CN) to a static overlay address.
func (o *OpenVPN) CCDEntry(overlayIP string) (string, error) {
	mask, err := o.Netmask()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ifconfig-push %s %s\n", overlayIP, mask), nil
}

// ClientCN returns the OpenVPN client common-name (and ccd filename) for a host —
// its stable UUID, so the pinned address can never be spoofed by a chosen hostname.
func ClientCN(hostID string) string { return "fleet-h-" + hostID }

// EnsureJumpMaterial issues the jump-host OpenVPN server certificate (SAN = the
// jump endpoint host) and returns the CA cert + server cert/key PEM to install.
func (o *OpenVPN) EnsureJumpMaterial(ctx context.Context) (caPEM, certPEM, keyPEM []byte, err error) {
	host, _ := splitEndpoint(o.endpoint(), o.cfg.OVPNPort)
	var dns []string
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	} else if host != "" {
		dns = append(dns, host)
	}
	certPEM, keyPEM, err = o.pki.IssueServer("fleet-overlay-server", dns, ips, clientCertTTL)
	if err != nil {
		return nil, nil, nil, err
	}
	return o.pki.CACertPEM(), certPEM, keyPEM, nil
}

// IssueHostMaterial issues a managed host's client certificate (CN bound to the
// host UUID) and returns the CA + cert/key PEM plus the common name, recording it.
func (o *OpenVPN) IssueHostMaterial(ctx context.Context, hostID uuid.UUID) (caPEM, certPEM, keyPEM []byte, cn string, err error) {
	cn = ClientCN(hostID.String())
	certPEM, keyPEM, serial, err := o.pki.IssueClient(cn, clientCertTTL)
	if err != nil {
		return nil, nil, nil, "", err
	}
	_ = o.pki.RecordClient(ctx, hostID, cn, serial, time.Now().Add(clientCertTTL))
	return o.pki.CACertPEM(), certPEM, keyPEM, cn, nil
}

// JumpServerScript provisions and (idempotently) starts the OpenVPN server on the
// jump host: installs openvpn, writes the CA/server material + config + ccd dir, and
// starts the daemon only if it isn't already running (so re-enrollment never drops
// live tunnels).
// runningCheck renders a shell function that reports whether an openvpn process is
// running against confPath.
//
// It matches on the process NAME (pgrep -x openvpn) and then reads /proc/<pid>/cmdline
// to confirm the config, and it must keep doing both. The obvious `pgrep -f 'openvpn
// .*server.conf'` is what shipped, and it always answered yes: Fleet runs these
// scripts as `sh -c "<the whole script>"`, so the script's own shell has that exact
// command line in its argv and pgrep -f matches command lines. The server was
// therefore reported "already running" on every enrollment and never actually
// started — a whole overlay that had never once come up, with green steps behind it.
// pgrep -x matches comm, which is "sh", so it cannot match the caller.
//
// (The Docker validation harness missed this because it runs the script from a FILE:
// `sh jump-server.sh` puts nothing but the filename in argv.)
func runningCheck(fn, confPath string) string {
	return fmt.Sprintf(`%[1]s() {
  for _p in $(pgrep -x openvpn 2>/dev/null); do
    if tr '\0' ' ' < "/proc/$_p/cmdline" 2>/dev/null | grep -qF -- '%[2]s'; then return 0; fi
  done
  return 1
}
`, fn, confPath)
}

func (o *OpenVPN) JumpServerScript(caPEM, certPEM, keyPEM []byte, serverConf string) string {
	return fmt.Sprintf(`set -e
if ! command -v openvpn >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq openvpn >/dev/null 2>&1
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q openvpn >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then yum install -y -q openvpn >/dev/null 2>&1
  elif command -v apk >/dev/null 2>&1; then apk add --no-cache openvpn >/dev/null 2>&1
  fi
fi
mkdir -p %[1]s/ccd
umask 077
cat > %[1]s/ca.crt <<'FLEOF'
%[2]sFLEOF
cat > %[1]s/server.crt <<'FLEOF'
%[3]sFLEOF
cat > %[1]s/server.key <<'FLEOF'
%[4]sFLEOF
cat > %[1]s/server.conf <<'FLEOF'
%[5]sFLEOF
%[6]s%[7]sif ovpn_server_running; then
  echo OVPN_SERVER_ALREADY_RUNNING
else
  # --daemon detaches before the tun/bind work, so its failures land nowhere unless
  # a log is named. That log is the only account of WHY a start failed, and it is
  # tailed into the enrollment step below.
  : > %[1]s/server.log
  openvpn --config %[1]s/server.conf --daemon fleet-overlay \
    --writepid /run/fleet-ovpn.pid --log-append %[1]s/server.log || true
  _i=0
  while [ $_i -lt 10 ]; do
    if ovpn_server_running; then break; fi
    sleep 1; _i=$((_i+1))
  done
  if ovpn_server_running; then
    echo OVPN_SERVER_STARTED
  else
    echo OVPN_SERVER_START_FAILED
    echo '--- openvpn server log ---'
    tail -n 15 %[1]s/server.log 2>/dev/null
  fi
fi`, fleetDir, string(caPEM), string(certPEM), string(keyPEM), serverConf,
		o.peerIsolationScript(), runningCheck("ovpn_server_running", fleetDir+"/server.conf"))
}

// peerIsolationScript renders the fragment of JumpServerScript that keeps the
// OpenVPN overlay strict hub-and-spoke, or "" when isolation is turned off.
//
// OpenVPN's own `client-to-client` is already unset (the default), but that alone
// does NOT isolate clients under `topology subnet`: a packet from one client for
// another arrives on the server's tun, the kernel routes it straight back out the
// same tun (ip_forward is on so the jump host can route), and OpenVPN then hands
// it to the destination client. So the isolation has to be a forwarding rule, the
// same as for the WireGuard hub in deploy/testfabric/jumphost/entrypoint.sh.
//
// The rule matches on the overlay subnet rather than the interface, because
// OpenVPN picks its tun device number at runtime — the subnet is the one thing
// known here. Nothing Fleet does is affected: every connection it makes to a
// managed host is dialed FROM the jump host, so it leaves via OUTPUT and is not
// a forwarded flow.
//
// Idempotent (-C before -I) so re-enrollment cannot stack duplicate rules, and
// non-fatal under `set -e` so a jump host with no usable iptables still gets its
// OpenVPN server — it just reports the isolation it could not apply.
func (o *OpenVPN) peerIsolationScript() string {
	if !o.cfg.OverlayPeerIsolation {
		return ""
	}
	// Re-parse rather than interpolating the configured string: this value is going
	// into a shell command line, and ParseCIDR's normalized form is the only shape
	// that can come out. An unparseable subnet fails ServerConfig anyway, so
	// provisioning never reaches here with one.
	_, ipnet, err := net.ParseCIDR(o.cfg.OVPNSubnet)
	if err != nil {
		return ""
	}
	// The deny IS iptables, so provide it the same way this script provides openvpn.
	// Without it the jump host forwards freely between managed hosts and the only
	// signal is the OVPN_PEER_ISOLATION_FAILED line below — a security control that
	// goes missing quietly is the failure mode worth spending a package install on.
	return fmt.Sprintf(`if ! command -v iptables >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then { apt-get update -qq && apt-get install -y -qq iptables; } >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q iptables >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then yum install -y -q iptables >/dev/null 2>&1 || true
  elif command -v apk >/dev/null 2>&1; then apk add --no-cache iptables >/dev/null 2>&1 || true
  fi
fi
if iptables -C FORWARD -s %[1]s -d %[1]s -j DROP >/dev/null 2>&1 \
   || iptables -I FORWARD 1 -s %[1]s -d %[1]s -j DROP >/dev/null 2>&1; then
  echo OVPN_PEER_ISOLATION_OK
else
  echo OVPN_PEER_ISOLATION_FAILED
fi
`, ipnet.String())
}

// JumpCCDScript pins a host's overlay address on the jump server by writing its ccd
// entry (read by the server when the client connects — no server restart needed).
func (o *OpenVPN) JumpCCDScript(cn, ccdEntry string) string {
	return fmt.Sprintf(`set -e
mkdir -p %[1]s/ccd
cat > %[1]s/ccd/%[2]s <<'FLEOF'
%[3]sFLEOF
echo OVPN_CCD_WRITTEN`, fleetDir, cn, ccdEntry)
}

// JumpCCDRemoveScript drops a host's pinned address from the server. The client
// certificate is left valid — a host moving to another transport has not been
// revoked, and re-enrolling it back onto this overlay should not need a new one —
// but with no ccd entry the server no longer holds an address for it.
func (o *OpenVPN) JumpCCDRemoveScript(cn string) string {
	return fmt.Sprintf(`if [ -f %[1]s/ccd/%[2]s ]; then rm -f %[1]s/ccd/%[2]s; echo OVPN_CCD_REMOVED; else echo OVPN_CCD_ABSENT; fi`,
		fleetDir, cn)
}

// RetireJump implements Overlay.
func (o *OpenVPN) RetireJump(ctx context.Context, hostID uuid.UUID, jumpRun RunFunc) (string, error) {
	out, err := jumpRun(o.JumpCCDRemoveScript(ClientCN(hostID.String())))
	if err != nil {
		return "", fmt.Errorf("remove the pinned address on the jump host: %v: %s", err, oneLine(out))
	}
	if strings.Contains(out, "OVPN_CCD_REMOVED") {
		return "pinned overlay address removed from the openvpn server", nil
	}
	return "", nil
}

// RetireHostScript implements Overlay: stop the client, keep it from restarting on
// boot, and set the config aside.
//
// The client material (ca/cert/key) is deliberately left in place — a host moved
// back later re-uses the certificate Fleet already issued it, and the files are
// root-only. The config is renamed rather than deleted so an operator can see what
// was retired, matching how the WireGuard teardown treats wg-quick's config.
func (o *OpenVPN) RetireHostScript() HostBringup {
	return HostBringup{
		Marker: "OVPN_RETIRED",
		Script: fmt.Sprintf(`set +e
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now openvpn@fleet-overlay >/dev/null 2>&1
  systemctl disable --now openvpn-client@fleet-overlay >/dev/null 2>&1
fi
# Whatever systemd did or did not manage, stop any daemon still running against
# this config. Matched by process NAME plus /proc: a command-line match would also
# hit this very script, whose own text contains the config path.
for _p in $(pgrep -x openvpn 2>/dev/null); do
  if tr '\0' ' ' < "/proc/$_p/cmdline" 2>/dev/null | grep -qF -- '%[1]s/client.ovpn'; then
    kill "$_p" 2>/dev/null
  fi
done
rm -f /run/fleet-ovpn-client.pid
for f in /etc/openvpn/fleet-overlay.conf /etc/openvpn/client/fleet-overlay.conf; do
  [ -f "$f" ] && mv -f "$f" "$f.fleet-disabled"
done
if [ -f %[1]s/client.ovpn ]; then mv -f %[1]s/client.ovpn %[1]s/client.ovpn.fleet-disabled; fi
echo OVPN_RETIRED`, fleetDir),
	}
}

// HostInstallScript installs openvpn on a managed host, writes its client material +
// config, and brings up the persistent tunnel (systemd where available, else a
// backgrounded daemon).
func (o *OpenVPN) HostInstallScript(caPEM, certPEM, keyPEM []byte, clientConf, overlayIP string) string {
	return fmt.Sprintf(`set -e
if ! command -v openvpn >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq openvpn >/dev/null 2>&1
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q openvpn >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then yum install -y -q openvpn >/dev/null 2>&1
  elif command -v apk >/dev/null 2>&1; then apk add --no-cache openvpn >/dev/null 2>&1
  fi
fi
command -v openvpn >/dev/null 2>&1 || { echo OVPN_INSTALL_FAILED; exit 1; }
mkdir -p %[1]s
umask 077
cat > %[1]s/ca.crt <<'FLEOF'
%[2]sFLEOF
cat > %[1]s/client.crt <<'FLEOF'
%[3]sFLEOF
cat > %[1]s/client.key <<'FLEOF'
%[4]sFLEOF
cat > %[1]s/client.ovpn <<'FLEOF'
%[5]sFLEOF
%[6]s%[7]sif ! ovpn_client_running; then
  if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
    cp %[1]s/client.ovpn /etc/openvpn/fleet-overlay.conf 2>/dev/null || cp %[1]s/client.ovpn /etc/openvpn/client/fleet-overlay.conf 2>/dev/null || true
    systemctl enable --now openvpn@fleet-overlay >/dev/null 2>&1 || systemctl enable --now openvpn-client@fleet-overlay >/dev/null 2>&1 || \
      openvpn --config %[1]s/client.ovpn --daemon fleet-overlay --writepid /run/fleet-ovpn-client.pid --log-append %[1]s/client.log || true
  else
    : > %[1]s/client.log
    openvpn --config %[1]s/client.ovpn --daemon fleet-overlay --writepid /run/fleet-ovpn-client.pid --log-append %[1]s/client.log || true
  fi
fi
# The tunnel is not up because a process started — it is up when the server has
# pushed this host its overlay address. Wait for that address to appear on a tun
# device and report what was actually observed. Reporting the address Fleet MEANT
# to assign, off a script that printed success unconditionally, is what let a
# never-configured overlay pass for a working one.
#
# The window is generous because the first connect legitimately takes time: DNS, a
# NAT hairpin when the host sits on the jump host's LAN, and openvpn's own retry
# backoff after any attempt that lands while the server is restarting. A 20s window
# failed enrollments whose tunnel then came up seconds later and stayed up — the
# worst outcome, since the operator is told it did not work while it did.
#
# It waits for the address the server was told to pin, not merely for any tun
# device, so a bring-up on a pool address (the ccd entry not applying) is not
# mistaken for success — but whatever was seen is reported either way.
OVPN_WANT=%[8]s
OVPN_IP=
_i=0
while [ $_i -lt 60 ]; do
  for _a in $(ip -4 -br addr show 2>/dev/null | awk '$1 ~ /^(tun|tap)/ {print $3}' | cut -d/ -f1); do
    if [ "$_a" = "$OVPN_WANT" ]; then OVPN_IP=$_a; break; fi
    if [ -z "$OVPN_IP" ]; then OVPN_IP=$_a; fi
  done
  if [ -n "$OVPN_WANT" ] && [ "$OVPN_IP" = "$OVPN_WANT" ]; then break; fi
  if [ -z "$OVPN_WANT" ] && [ -n "$OVPN_IP" ]; then break; fi
  sleep 1; _i=$((_i+1))
done
echo "OVPN_WAITED=${_i}s"
if [ -n "$OVPN_IP" ]; then
  echo "OVPN_HOST_IP=$OVPN_IP"
  echo OVPN_HOST_CONFIGURED
else
  # Diagnostics only — nothing here may abort the script. "set -e" is still on, and
  # journalctl/systemctl status exit non-zero for a unit that is merely inactive:
  # that killed this block before it printed anything, so a failed enrollment showed
  # an empty log and said nothing about why.
  set +e
  echo OVPN_HOST_NO_TUNNEL
  # The address the client was told to dial. When the tunnel never comes up this is
  # almost always the answer — the server's UDP port is not reachable from here —
  # and it is not otherwise visible to whoever reads the enrollment error.
  echo "OVPN_REMOTE=$(awk '/^remote /{print $2\":\"$3; exit}' %[1]s/client.ovpn 2>/dev/null)"
  echo '--- openvpn client log ---'
  if [ -s %[1]s/client.log ]; then
    tail -n 20 %[1]s/client.log
  else
    echo '(no client.log: started under systemd — unit state follows)'
    systemctl --no-pager --lines=20 status openvpn@fleet-overlay 2>/dev/null
    systemctl --no-pager --lines=20 status openvpn-client@fleet-overlay 2>/dev/null
    journalctl -u openvpn@fleet-overlay -u openvpn-client@fleet-overlay -n 20 --no-pager 2>/dev/null
  fi
  # The verdict is the marker, not the exit status: these diagnostics all exit
  # non-zero for an inactive unit, and letting that become the script's status buried
  # the report under a bare "Process exited with status 1".
  true
fi`, fleetDir, string(caPEM), string(certPEM), string(keyPEM), clientConf,
		o.hostIsolationInstall(), runningCheck("ovpn_client_running", fleetDir+"/client.ovpn"), overlayIP)
}

// hostIsolationInstall renders the fragment of HostInstallScript that lays down the
// `up` script the client config references, and makes sure the host can actually run
// it. Written before the tunnel is started, so the very first connect is already
// isolated — there is no window in which the host is up on the overlay without its
// filter.
//
// iptables is a REQUIREMENT of this overlay's isolation, not an assumption. OpenVPN
// has no AllowedIPs: a filter on the tunnel device is the only thing isolating the
// host at its own end, and the up script deliberately fails open when iptables is
// missing (under script-security 2 a failing up script aborts the tunnel, and an
// unreachable host is worse than an unfiltered one). The consequence is that a host
// without iptables joins the overlay silently unisolated, with the only trace a line
// in its own OpenVPN log. So install it the same way openvpn itself is installed, and
// say so when that fails.
func (o *OpenVPN) hostIsolationInstall() string {
	body := o.hostIsolationScript()
	if body == "" {
		return ""
	}
	return fmt.Sprintf(`if ! command -v iptables >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then { apt-get update -qq && apt-get install -y -qq iptables; } >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q iptables >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then yum install -y -q iptables >/dev/null 2>&1 || true
  elif command -v apk >/dev/null 2>&1; then apk add --no-cache iptables >/dev/null 2>&1 || true
  fi
fi
command -v iptables >/dev/null 2>&1 || echo OVPN_IPTABLES_MISSING
cat > %[1]s/peer-isolation.sh <<'FLEOF'
%[2]sFLEOF
chmod 0700 %[1]s/peer-isolation.sh
`, fleetDir, body)
}

// endpoint returns the OpenVPN endpoint managed hosts dial: the DB/settings value
// isn't overlay-specific, so reuse the WG jump endpoint's host with the OVPN port.
func (o *OpenVPN) endpoint() string {
	ep := o.cfg.WGJumpEndpoint
	if ep == "" {
		ep = o.cfg.JumpHost
	}
	host, _ := splitEndpoint(ep, o.cfg.OVPNPort)
	return net.JoinHostPort(host, fmt.Sprintf("%d", o.cfg.OVPNPort))
}

// splitEndpoint parses "host:port"; falls back to defPort when no port is given.
func splitEndpoint(endpoint string, defPort int) (string, int) {
	if h, p, err := net.SplitHostPort(endpoint); err == nil {
		var port int
		fmt.Sscanf(p, "%d", &port)
		if port == 0 {
			port = defPort
		}
		return h, port
	}
	return strings.TrimSpace(endpoint), defPort
}
