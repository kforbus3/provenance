package enrollment

import (
	"strings"
	"testing"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/models"
)

func switchTestService() *Service {
	return &Service{cfg: &config.Config{
		WGSubnet: "10.100.0.0/24", WGJumpIP: "10.100.0.1", WGPort: 51820, WGInterface: "wgfleet",
		OVPNSubnet: "10.101.0.0/24", OVPNJumpIP: "10.101.0.1", OVPNPort: 1194,
	}}
}

// The two overlays must be numbered from different pools. They terminate on the same
// jump host and each puts its own address on its interface, so one shared subnet
// gives that host two connected routes for one prefix — resolved once, for the whole
// prefix — and strands every host behind the losing interface.
func TestOverlayPlansAreSeparatePools(t *testing.T) {
	s := switchTestService()
	wg, ovpn := s.plan("wireguard"), s.plan("openvpn")

	if wg.Subnet == ovpn.Subnet {
		t.Fatalf("both overlays draw from %s — a host on one is unreachable when the other is up", wg.Subnet)
	}
	if wg.JumpIP == ovpn.JumpIP {
		t.Errorf("both overlays claim jump address %s", wg.JumpIP)
	}
	// An unknown or empty transport is WireGuard, matching effectiveOverlay.
	for _, name := range []string{"", "wireguard", "something-else"} {
		if got := s.plan(name).Subnet; got != wg.Subnet {
			t.Errorf("plan(%q) = %s, want the WireGuard pool %s", name, got, wg.Subnet)
		}
	}
}

// A host keeps its address while it stays on one overlay, and is renumbered when it
// moves — that renumbering is the whole reason the switch works, so it must be
// visible in the address the assignment resolves to, not silently skipped.
func TestOverlayAddressBelongsToThePlanItIsJoining(t *testing.T) {
	s := switchTestService()
	for _, tc := range []struct {
		name    string
		addr    string
		joining string
		keeps   bool
	}{
		{"wireguard host staying on wireguard", "10.100.0.27", "wireguard", true},
		{"openvpn host staying on openvpn", "10.101.0.27", "openvpn", true},
		{"wireguard host moving to openvpn", "10.100.0.27", "openvpn", false},
		{"openvpn host moving to wireguard", "10.101.0.27", "wireguard", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := s.plan(tc.joining)
			if got := isOverlayAddr(tc.addr, p.JumpIP); got != tc.keeps {
				t.Errorf("address %s in the %s pool = %v, want %v — a host that keeps an address "+
					"from the overlay it just left is dialed into the wrong transport",
					tc.addr, tc.joining, got, tc.keeps)
			}
		})
	}
}

// The transport a host is leaving drives which teardown runs. Getting this wrong in
// either direction leaves a client running against an overlay the host has left.
func TestPreviousOverlay(t *testing.T) {
	for _, tc := range []struct {
		name    string
		host    models.Host
		joining string
		want    string
	}{
		{"fresh host joins wireguard", models.Host{}, "wireguard", ""},
		{"fresh host joins openvpn", models.Host{}, "openvpn", ""},
		{"wireguard host re-enrolled on wireguard", models.Host{Enrolled: true, Overlay: "wireguard"}, "wireguard", ""},
		{"wireguard host switches to openvpn", models.Host{Enrolled: true, Overlay: "wireguard"}, "openvpn", "wireguard"},
		{"openvpn host switches back", models.Host{Enrolled: true, Overlay: "openvpn"}, "wireguard", "openvpn"},
		// Enrolled before per-host overlays existed: an empty overlay is WireGuard,
		// and moving such a host to OpenVPN still has to retire its tunnel.
		{"legacy host switches to openvpn", models.Host{Enrolled: true, WGAddress: "10.100.0.5"}, "openvpn", "wireguard"},
		{"legacy host re-enrolled on wireguard", models.Host{Enrolled: true, WGAddress: "10.100.0.5"}, "wireguard", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := previousOverlay(&tc.host, tc.joining); got != tc.want {
				t.Errorf("previousOverlay = %q, want %q", got, tc.want)
			}
		})
	}
}

// Both teardown scripts must be POSIX sh, best-effort, and must set the old config
// aside rather than delete it — a host moved back re-uses the identity it already
// has, and an operator has to be able to see what was retired.
func TestTeardownScriptsAreBestEffortAndReversible(t *testing.T) {
	s := switchTestService()
	wg := s.wgTeardownScript()
	if !strings.HasPrefix(wg, "set +e") {
		t.Error("WireGuard teardown is not best-effort")
	}
	if !strings.Contains(wg, "$IF.conf.fleet-disabled") {
		t.Error("WireGuard teardown does not preserve the retired config")
	}
	if !strings.Contains(wg, "systemctl disable --now wg-quick@$IF") {
		t.Error("WireGuard teardown leaves the tunnel enabled on boot")
	}
}
