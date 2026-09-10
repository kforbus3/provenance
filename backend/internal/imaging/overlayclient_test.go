package imaging

import "testing"

// The overlay client has to be IN the image.
//
// Enrollment installs openvpn (or wireguard-tools) onto a running host with the
// package manager, which puts it in /usr — and /usr is exactly what an A/B
// update replaces. The config, certificates and keys live in /etc and survive,
// because the overlay carries /etc across. The binary and its systemd unit do
// not.
//
// So a machine enrolled on the VPN, updated once, comes up on the new slot with
// a complete OpenVPN configuration, its certificate, its key, and nothing to run
// them with:
//
//	command -v openvpn      → (nothing)
//	systemctl is-enabled …  → No such file or directory
//	ls /etc/openvpn/fleet/  → ca.crt  client.crt  client.ovpn
//
// and silently leaves the overlay. Observed on a real machine. It is not a rare
// case; it is every A/B machine, on its first update.

func TestOverlayClientIsNamedForEachOverlay(t *testing.T) {
	for _, tc := range []struct{ overlay, want string }{
		{"openvpn", "openvpn"},
		{"wireguard", "wireguard-tools"},
		{"OpenVPN", "openvpn"}, // the setting is not case-normalised anywhere else
		{" wireguard ", "wireguard-tools"},
	} {
		if got := overlayClientPackage(tc.overlay); got != tc.want {
			t.Errorf("overlayClientPackage(%q) = %q, want %q", tc.overlay, got, tc.want)
		}
	}
}

// Unset means the deployment has not chosen one. Guessing would put a VPN client
// on every machine for an overlay that may never be used.
func TestNoOverlayMeansNoPackage(t *testing.T) {
	for _, overlay := range []string{"", "   ", "none", "something-else"} {
		if got := overlayClientPackage(overlay); got != "" {
			t.Errorf("overlayClientPackage(%q) = %q, want empty", overlay, got)
		}
	}
}
