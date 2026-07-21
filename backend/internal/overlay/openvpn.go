// Package overlay generates the FIPS OpenVPN overlay's server, client, and per-host
// configuration. It is the parallel sibling of the WireGuard enrollment path
// (internal/enrollment): selected only when FLEET_OVERLAY=openvpn, so the default
// WireGuard overlay is completely untouched.
//
// The overlay reuses the WireGuard subnet/jump-IP and the same hosts.wg_address
// column for a host's assigned overlay address, so the SSH gateway's address
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

// subnetParts splits WGSubnet ("10.100.0.0/24") into network + dotted netmask for
// the OpenVPN `server` directive and ccd `ifconfig-push`.
func (o *OpenVPN) subnetParts() (network, netmask string, err error) {
	_, ipnet, err := net.ParseCIDR(o.cfg.WGSubnet)
	if err != nil {
		return "", "", fmt.Errorf("bad FLEET_WG_SUBNET %q: %w", o.cfg.WGSubnet, err)
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
// first host of the subnet (WGJumpIP) as its own tun address and pins static
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
`, host, port, fleetDir, fleetDir, fleetDir)
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
if pgrep -f 'openvpn .*%[1]s/server.conf' >/dev/null 2>&1; then
  echo OVPN_SERVER_ALREADY_RUNNING
else
  openvpn --config %[1]s/server.conf --daemon fleet-overlay --writepid /run/fleet-ovpn.pid
  sleep 1
  pgrep -f 'openvpn .*%[1]s/server.conf' >/dev/null 2>&1 && echo OVPN_SERVER_STARTED || echo OVPN_SERVER_START_FAILED
fi`, fleetDir, string(caPEM), string(certPEM), string(keyPEM), serverConf)
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

// HostInstallScript installs openvpn on a managed host, writes its client material +
// config, and brings up the persistent tunnel (systemd where available, else a
// backgrounded daemon).
func (o *OpenVPN) HostInstallScript(caPEM, certPEM, keyPEM []byte, clientConf string) string {
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
if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
  cp %[1]s/client.ovpn /etc/openvpn/fleet-overlay.conf 2>/dev/null || cp %[1]s/client.ovpn /etc/openvpn/client/fleet-overlay.conf 2>/dev/null || true
  systemctl enable --now openvpn@fleet-overlay >/dev/null 2>&1 || systemctl enable --now openvpn-client@fleet-overlay >/dev/null 2>&1 || \
    openvpn --config %[1]s/client.ovpn --daemon fleet-overlay --writepid /run/fleet-ovpn-client.pid
else
  pgrep -f 'openvpn .*%[1]s/client.ovpn' >/dev/null 2>&1 || openvpn --config %[1]s/client.ovpn --daemon fleet-overlay --writepid /run/fleet-ovpn-client.pid
fi
sleep 2
(ip -4 addr show dev tun0 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}') | head -1 | sed 's/^/OVPN_HOST_IP=/'
echo OVPN_HOST_CONFIGURED`, fleetDir, string(caPEM), string(certPEM), string(keyPEM), clientConf)
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
