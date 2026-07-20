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

// swanDir is where Fleet's strongSwan material lives on both the jump host and managed
// hosts (the standard swanctl layout).
const swanDir = "/etc/swanctl"

// FIPS-approved IKEv2 proposals: AES-256 + SHA-256 PRF/integrity + ECDHE P-256 for the
// IKE SA, and AES-256-GCM + PFS ECP-256 for the child (ESP) SA. No curve25519/chacha.
const (
	swanIKEProposals = "aes256-sha256-ecp256"
	swanESPProposals = "aes256gcm16-ecp256"
	swanServerID     = "fleet-overlay-server"
)

// StrongSwan provisions Fleet's IPsec/IKEv2 overlay (strongSwan + swanctl), an
// alternative to OpenVPN for FIPS deployments. Like OpenVPN it authenticates peers
// with X.509 certs from the shared overlay PKI and assigns a stable per-host address;
// unlike OpenVPN the address is a virtual IP pinned server-side to the client's cert
// identity (spoof-proof), and traffic rides ESP rather than a TLS tunnel.
type StrongSwan struct {
	cfg *config.Config
	pki *overlaypki.PKI
}

// NewStrongSwan constructs the strongSwan overlay provisioner.
func NewStrongSwan(cfg *config.Config, pki *overlaypki.PKI) *StrongSwan {
	return &StrongSwan{cfg: cfg, pki: pki}
}

// Name implements Overlay.
func (s *StrongSwan) Name() string { return "strongswan" }

// endpointHost returns the jump address managed hosts initiate IKE to (UDP 500/4500).
func (s *StrongSwan) endpointHost() string {
	ep := s.cfg.WGJumpEndpoint
	if ep == "" {
		ep = s.cfg.JumpHost
	}
	if h, _, err := net.SplitHostPort(ep); err == nil {
		return h
	}
	return strings.TrimSpace(ep)
}

// EnsureServer implements Overlay: install strongSwan on the jump host, drop the CA +
// server cert/key, give the jump its overlay source IP, and start charon. Idempotent.
func (s *StrongSwan) EnsureServer(ctx context.Context, jumpRun RunFunc) error {
	if err := s.pki.EnsureCA(ctx); err != nil {
		return fmt.Errorf("overlay PKI: %w", err)
	}
	// The server cert's SAN carries the jump endpoint (informational; IKEv2 matches on
	// the configured id, not the hostname).
	host := s.endpointHost()
	var dns []string
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	} else if host != "" {
		dns = append(dns, host)
	}
	certPEM, keyPEM, err := s.pki.IssueServer(swanServerID, dns, ips, clientCertTTL)
	if err != nil {
		return fmt.Errorf("issue jump IPsec server certificate: %w", err)
	}
	out, err := jumpRun(s.jumpServerScript(s.pki.CACertPEM(), certPEM, keyPEM))
	if err != nil {
		return fmt.Errorf("start jump strongSwan: %v: %s", err, oneLine(out))
	}
	if !strings.Contains(out, "IPSEC_SERVER_READY") {
		return fmt.Errorf("jump strongSwan did not come up: %s", oneLine(out))
	}
	return nil
}

// ProvisionHost implements Overlay: pin the host's virtual IP to its cert identity on
// the jump responder, then install strongSwan on the host and initiate the tunnel.
func (s *StrongSwan) ProvisionHost(ctx context.Context, hostID uuid.UUID, overlayIP, endpoint string, hostRun, jumpRun RunFunc) (string, error) {
	cn := ClientCN(hostID.String())
	certPEM, keyPEM, serial, err := s.pki.IssueClient(cn, clientCertTTL)
	if err != nil {
		return "", fmt.Errorf("issue host IPsec certificate: %w", err)
	}
	_ = s.pki.RecordClient(ctx, hostID, cn, serial, time.Now().Add(clientCertTTL))

	// 1) Responder: write this host's connection fragment (IP pinned to its cert CN via
	//    a single-address pool) and reload.
	if out, jerr := jumpRun(s.jumpConnScript(cn, overlayIP)); jerr != nil {
		return "", fmt.Errorf("pin IPsec address on jump: %v: %s", jerr, oneLine(out))
	}

	// 2) Initiator: install strongSwan on the host, drop its material + config, initiate.
	host := endpoint
	if h, _, e := net.SplitHostPort(endpoint); e == nil {
		host = h
	}
	out, herr := hostRun(s.hostInstallScript(s.pki.CACertPEM(), certPEM, keyPEM, cn, host, overlayIP))
	if herr != nil || strings.Contains(out, "IPSEC_INSTALL_FAILED") || !strings.Contains(out, "IPSEC_HOST_CONFIGURED") {
		return "", fmt.Errorf("install strongSwan on host: %v: %s", herr, oneLine(out))
	}
	return fmt.Sprintf("IPsec tunnel initiated (addr %s)", overlayIP), nil
}

// jumpServerScript installs strongSwan on the jump host, writes the CA + server
// material, gives the jump its overlay source IP (WGJumpIP/32 on a dummy iface), and
// starts charon. The base swanctl.conf includes per-host fragments from conf.d.
func (s *StrongSwan) jumpServerScript(caPEM, certPEM, keyPEM []byte) string {
	return fmt.Sprintf(`set -e
if ! command -v swanctl >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq strongswan strongswan-swanctl >/dev/null 2>&1
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q strongswan strongswan-swanctl >/dev/null 2>&1 || dnf install -y -q strongswan >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then yum install -y -q strongswan >/dev/null 2>&1
  elif command -v apk >/dev/null 2>&1; then apk add --no-cache strongswan >/dev/null 2>&1
  fi
fi
command -v swanctl >/dev/null 2>&1 || { echo IPSEC_INSTALL_FAILED; exit 1; }
mkdir -p %[1]s/x509ca %[1]s/x509 %[1]s/private %[1]s/conf.d
umask 077
cat > %[1]s/x509ca/fleet-ca.pem <<'FLEOF'
%[2]sFLEOF
cat > %[1]s/x509/fleet-server.pem <<'FLEOF'
%[3]sFLEOF
cat > %[1]s/private/fleet-server.key <<'FLEOF'
%[4]sFLEOF
cat > %[1]s/swanctl.conf <<'FLEOF'
include conf.d/*.conf
FLEOF
# Give the jump an overlay source address so it can reach each host's virtual IP.
ip link show fleet-ipsec >/dev/null 2>&1 || ip link add fleet-ipsec type dummy 2>/dev/null || true
ip link set fleet-ipsec up 2>/dev/null || true
ip addr replace %[5]s/32 dev fleet-ipsec 2>/dev/null || true
# Start charon (service name varies by distro/packaging).
systemctl enable --now strongswan >/dev/null 2>&1 \
  || systemctl enable --now strongswan-swanctl >/dev/null 2>&1 \
  || systemctl enable --now strongswan-starter >/dev/null 2>&1 \
  || (pgrep -x charon >/dev/null 2>&1 || (ipsec start >/dev/null 2>&1 || /usr/lib/ipsec/charon >/dev/null 2>&1 &))
sleep 2
swanctl --load-all >/dev/null 2>&1 || true
pgrep -x charon >/dev/null 2>&1 && echo IPSEC_SERVER_READY || echo IPSEC_SERVER_START_FAILED`,
		swanDir, string(caPEM), string(certPEM), string(keyPEM), s.cfg.WGJumpIP)
}

// jumpConnScript writes the responder connection fragment for one host — its virtual
// IP is a single-address pool bound to a connection matched by the client cert CN, so
// only that host can obtain that address — then reloads swanctl.
func (s *StrongSwan) jumpConnScript(cn, overlayIP string) string {
	conn := s.responderConn(cn, overlayIP)
	return fmt.Sprintf(`set -e
mkdir -p %[1]s/conf.d
umask 077
cat > %[1]s/conf.d/fleet-%[2]s.conf <<'FLEOF'
%[3]sFLEOF
swanctl --load-all >/dev/null 2>&1 || swanctl --load-conns >/dev/null 2>&1 || true
echo IPSEC_CONN_WRITTEN`, swanDir, cn, conn)
}

// responderConn is the jump-side swanctl connection + pool for a single host.
func (s *StrongSwan) responderConn(cn, overlayIP string) string {
	return fmt.Sprintf(`connections {
  %[1]s {
    version = 2
    proposals = %[4]s
    local_addrs = %%any
    remote_addrs = %%any
    pools = %[1]s
    local {
      auth = pubkey
      certs = fleet-server.pem
      id = %[5]s
    }
    remote {
      auth = pubkey
      cacerts = fleet-ca.pem
      id = %[1]s
    }
    children {
      fleet {
        local_ts = %[2]s/32
        remote_ts = %[3]s/32
        esp_proposals = %[6]s
        mode = tunnel
      }
    }
  }
}
pools {
  %[1]s {
    addrs = %[3]s/32
  }
}
`, cn, s.cfg.WGJumpIP, overlayIP, swanIKEProposals, swanServerID, swanESPProposals)
}

// hostInstallScript installs strongSwan on a managed host, writes its material +
// initiator config, and brings up the tunnel (requesting its pinned virtual IP).
func (s *StrongSwan) hostInstallScript(caPEM, certPEM, keyPEM []byte, cn, jumpHost, overlayIP string) string {
	conf := s.initiatorConf(cn, jumpHost, overlayIP)
	return fmt.Sprintf(`set -e
if ! command -v swanctl >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq strongswan strongswan-swanctl >/dev/null 2>&1
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q strongswan strongswan-swanctl >/dev/null 2>&1 || dnf install -y -q strongswan >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then yum install -y -q strongswan >/dev/null 2>&1
  elif command -v apk >/dev/null 2>&1; then apk add --no-cache strongswan >/dev/null 2>&1
  fi
fi
command -v swanctl >/dev/null 2>&1 || { echo IPSEC_INSTALL_FAILED; exit 1; }
mkdir -p %[1]s/x509ca %[1]s/x509 %[1]s/private %[1]s/conf.d
umask 077
cat > %[1]s/x509ca/fleet-ca.pem <<'FLEOF'
%[2]sFLEOF
cat > %[1]s/x509/fleet-client.pem <<'FLEOF'
%[3]sFLEOF
cat > %[1]s/private/fleet-client.key <<'FLEOF'
%[4]sFLEOF
cat > %[1]s/swanctl.conf <<'FLEOF'
%[5]sFLEOF
systemctl enable --now strongswan >/dev/null 2>&1 \
  || systemctl enable --now strongswan-swanctl >/dev/null 2>&1 \
  || systemctl enable --now strongswan-starter >/dev/null 2>&1 \
  || (pgrep -x charon >/dev/null 2>&1 || (ipsec start >/dev/null 2>&1 || /usr/lib/ipsec/charon >/dev/null 2>&1 &))
sleep 2
swanctl --load-all >/dev/null 2>&1 || true
swanctl --initiate --child fleet >/dev/null 2>&1 || true
sleep 2
echo IPSEC_HOST_CONFIGURED`, swanDir, string(caPEM), string(certPEM), string(keyPEM), conf)
}

// initiatorConf is the managed host's swanctl.conf: initiate IKEv2 to the jump,
// present the client cert, and request the pinned virtual IP.
func (s *StrongSwan) initiatorConf(cn, jumpHost, overlayIP string) string {
	return fmt.Sprintf(`connections {
  fleet {
    version = 2
    proposals = %[3]s
    remote_addrs = %[2]s
    vips = %[6]s
    local {
      auth = pubkey
      certs = fleet-client.pem
      id = %[1]s
    }
    remote {
      auth = pubkey
      cacerts = fleet-ca.pem
      id = %[4]s
    }
    children {
      fleet {
        local_ts = %[6]s/32
        remote_ts = %[5]s/32
        esp_proposals = %[7]s
        mode = tunnel
        start_action = start
      }
    }
  }
}
`, cn, jumpHost, swanIKEProposals, swanServerID, s.cfg.WGJumpIP, overlayIP, swanESPProposals)
}
