package imaging

import "testing"

// The overlay client has to be the one the MACHINE needs, not the one the
// deployment's default names.
//
// hosts.overlay is a per-host column; cfg.Overlay is only the fallback for a host
// that has not chosen. Keying on the config alone built an image carrying
// wireguard-tools -- correct for a deployment whose default resolves to WireGuard
// -- for a rebuild of a machine enrolled with openvpn. That image would have
// reproduced the exact failure it was built to fix: the machine comes up with a
// complete OpenVPN configuration, its certificates intact in /etc, and no
// openvpn binary to run any of it, then drops off the overlay silently.
//
// Caught by reading the built image's package manifest rather than by trusting
// the build's success, on a real rebuild of a real host.
func TestOverlayClientPackage(t *testing.T) {
	for _, c := range []struct{ mode, want string }{
		{"openvpn", "openvpn"},
		{"OpenVPN", "openvpn"}, // the column is not normalised on write
		{" wireguard ", "wireguard-tools"},
		{"wireguard", "wireguard-tools"},
		{"", ""},          // unset: guessing would put a VPN on every machine
		{"tailscale", ""}, // unknown: silence beats a wrong package
	} {
		if got := overlayClientPackage(c.mode); got != c.want {
			t.Errorf("overlayClientPackage(%q) = %q, want %q", c.mode, got, c.want)
		}
	}
}

// A fleet running both transports must get both clients, and in a stable order:
// an image is not built for one host, so it cannot pick.
func TestOverlayClientsForMixedFleet(t *testing.T) {
	pkgs := overlayClientsFor("wireguard", []string{"openvpn", "wireguard", "openvpn", ""})
	if len(pkgs) != 2 || pkgs[0] != "openvpn" || pkgs[1] != "wireguard-tools" {
		t.Fatalf("got %v, want [openvpn wireguard-tools] — sorted and deduplicated", pkgs)
	}

	// The configured default alone, when no host has overridden it.
	if pkgs := overlayClientsFor("openvpn", nil); len(pkgs) != 1 || pkgs[0] != "openvpn" {
		t.Errorf("got %v, want [openvpn]", pkgs)
	}

	// Nothing configured and no host enrolled: add nothing rather than guess.
	if pkgs := overlayClientsFor("", nil); len(pkgs) != 0 {
		t.Errorf("got %v, want none", pkgs)
	}
}
