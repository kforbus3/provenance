package overlay

import (
	"strings"
	"testing"

	"github.com/fleet-terminal/backend/internal/config"
)

// TestStrongSwanConfigShape checks the generated swanctl config carries the FIPS
// IKE/ESP proposals, pins the per-host virtual IP to the cert CN, and never emits a
// non-approved curve. Pure config generation — no PKI/DB needed.
func TestStrongSwanConfigShape(t *testing.T) {
	cfg := &config.Config{
		WGSubnet:       "10.100.0.0/24",
		WGJumpIP:       "10.100.0.1",
		WGJumpEndpoint: "vpn.example.com:51820",
	}
	s := NewStrongSwan(cfg, nil)

	responder := s.responderConn("fleet-h-abc123", "10.100.0.50")
	for _, want := range []string{
		"aes256-sha256-ecp256",      // FIPS IKE proposal (ECDHE P-256)
		"aes256gcm16-ecp256",        // FIPS ESP proposal
		"addrs = 10.100.0.50/32",    // single-address pool = the assigned vip
		"id = fleet-h-abc123",       // remote bound to the client cert CN (spoof-proof)
		"id = fleet-overlay-server", // local (server) identity
		"local_ts = 10.100.0.1/32",  // jump overlay source
		"remote_ts = 10.100.0.50/32",
		"cacerts = fleet-ca.pem",
	} {
		if !strings.Contains(responder, want) {
			t.Errorf("responder conn missing %q\n---\n%s", want, responder)
		}
	}

	initiator := s.initiatorConf("fleet-h-abc123", "vpn.example.com", "10.100.0.50")
	for _, want := range []string{
		"vips = 10.100.0.50", // request the pinned virtual IP
		"remote_addrs = vpn.example.com",
		"id = fleet-h-abc123",       // present our own cert identity
		"id = fleet-overlay-server", // require the jump's identity
		"start_action = start",      // auto-initiate on load
		"aes256gcm16-ecp256",
	} {
		if !strings.Contains(initiator, want) {
			t.Errorf("initiator conf missing %q\n---\n%s", want, initiator)
		}
	}

	// No non-FIPS key exchange anywhere.
	for _, cfgText := range []string{responder, initiator} {
		for _, bad := range []string{"curve25519", "x25519", "chacha", "curve448"} {
			if strings.Contains(strings.ToLower(cfgText), bad) {
				t.Errorf("config contains non-FIPS primitive %q", bad)
			}
		}
	}
}

func TestStrongSwanName(t *testing.T) {
	if got := NewStrongSwan(&config.Config{}, nil).Name(); got != "strongswan" {
		t.Errorf("Name() = %q, want strongswan", got)
	}
}
