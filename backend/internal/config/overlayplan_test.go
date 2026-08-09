package config

import (
	"strings"
	"testing"
)

// The two overlays must not share an address plan on a deployment that can run both.
// They terminate on the same jump host and each claims its own address on its own
// interface, so one subnet gives that host two connected routes for a single prefix —
// the kernel resolves that once, for the whole prefix, and every host behind the
// losing interface is unreachable.
func TestOverlayPlanDefaults(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		overlay, wgSubnet, wgJump string
		ovpnSubnet, ovpnJump      string
		wantSubnet, wantJump      string
	}{
		{
			name:    "wireguard deployment gets a separate openvpn pool",
			overlay: "wireguard", wgSubnet: "10.100.0.0/24", wgJump: "10.100.0.1",
			wantSubnet: "10.101.0.0/24", wantJump: "10.101.0.1",
		},
		{
			// An existing FIPS fleet already holds addresses out of FLEET_WG_SUBNET.
			// Moving the pool underneath it would invalidate every enrolled address at
			// once, and there is no WireGuard hub for it to collide with.
			name:    "openvpn-only deployment keeps its existing pool",
			overlay: "openvpn", wgSubnet: "10.100.0.0/24", wgJump: "10.100.0.1",
			wantSubnet: "10.100.0.0/24", wantJump: "10.100.0.1",
		},
		{
			name:    "explicit subnet wins, jump address derived",
			overlay: "wireguard", wgSubnet: "10.100.0.0/24", wgJump: "10.100.0.1",
			ovpnSubnet: "172.20.5.0/24",
			wantSubnet: "172.20.5.0/24", wantJump: "172.20.5.1",
		},
		{
			name:    "explicit jump address wins",
			overlay: "wireguard", wgSubnet: "10.100.0.0/24", wgJump: "10.100.0.1",
			ovpnSubnet: "172.20.5.0/24", ovpnJump: "172.20.5.9",
			wantSubnet: "172.20.5.0/24", wantJump: "172.20.5.9",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{
				Overlay: tc.overlay, WGSubnet: tc.wgSubnet, WGJumpIP: tc.wgJump,
				OVPNSubnet: tc.ovpnSubnet, OVPNJumpIP: tc.ovpnJump,
			}
			applyOverlayDefaults(c)
			if c.OVPNSubnet != tc.wantSubnet {
				t.Errorf("OVPNSubnet = %q, want %q", c.OVPNSubnet, tc.wantSubnet)
			}
			if c.OVPNJumpIP != tc.wantJump {
				t.Errorf("OVPNJumpIP = %q, want %q", c.OVPNJumpIP, tc.wantJump)
			}
			if err := c.validateOverlays(); err != nil {
				t.Errorf("resolved plan does not validate: %v", err)
			}
		})
	}
}

func TestOverlayPlanValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			// Partial overlap is never intentional: addresses handed out from one pool
			// would route into the other.
			name:    "overlapping subnets are refused",
			cfg:     Config{WGSubnet: "10.100.0.0/16", WGJumpIP: "10.100.0.1", OVPNSubnet: "10.100.5.0/24", OVPNJumpIP: "10.100.5.1"},
			wantErr: "overlaps",
		},
		{
			// Equal plans mean "this deployment speaks one overlay" — the shape an
			// OpenVPN-only install keeps, and legitimate.
			name: "identical subnets are allowed (single-overlay deployment)",
			cfg:  Config{WGSubnet: "10.100.0.0/24", WGJumpIP: "10.100.0.1", OVPNSubnet: "10.100.0.0/24", OVPNJumpIP: "10.100.0.1"},
		},
		{
			name:    "jump address outside its own subnet is refused",
			cfg:     Config{WGSubnet: "10.100.0.0/24", WGJumpIP: "10.100.0.1", OVPNSubnet: "10.101.0.0/24", OVPNJumpIP: "10.99.0.1"},
			wantErr: "inside FLEET_OVPN_SUBNET",
		},
		{
			name:    "unparseable subnet is refused",
			cfg:     Config{WGSubnet: "10.100.0.0/24", WGJumpIP: "10.100.0.1", OVPNSubnet: "not-a-cidr", OVPNJumpIP: "10.101.0.1"},
			wantErr: "not a valid CIDR",
		},
		{
			// Configs built directly in tests set no subnets at all.
			name: "empty plans are skipped",
			cfg:  Config{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validateOverlays()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted a plan that cannot work")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not explain the problem (want %q)", err, tc.wantErr)
			}
		})
	}
}
