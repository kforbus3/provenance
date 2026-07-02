package enrollment

import "testing"

func TestValidatePeerInputs(t *testing.T) {
	// A real `wg pubkey` output (43 base64 chars + '=').
	goodKey := "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	goodIP := "10.100.0.22"
	goodEP := "192.168.1.50:51820"

	if err := validatePeerInputs(goodKey, goodEP, goodIP); err != nil {
		t.Fatalf("legit inputs rejected: %v", err)
	}
	// Hostname endpoints and IPv6 endpoints must also pass.
	if err := validatePeerInputs(goodKey, "host-01.internal:51820", goodIP); err != nil {
		t.Fatalf("hostname endpoint rejected: %v", err)
	}
	if err := validatePeerInputs(goodKey, "[fd00::1]:51820", goodIP); err != nil {
		t.Fatalf("IPv6 endpoint rejected: %v", err)
	}

	bad := []struct {
		name                string
		pub, endpoint, wgIP string
	}{
		{"key shell injection", "A' ; id ; '", goodEP, goodIP},
		{"key command subst", "$(id)", goodEP, goodIP},
		{"key too short", "abc=", goodEP, goodIP},
		{"key wrong charset", "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8D!=", goodEP, goodIP},
		{"wgIP injection", goodKey, goodEP, "10.100.0.1; id"},
		{"wgIP not an ip", goodKey, goodEP, "not-an-ip"},
		{"endpoint host injection", goodKey, "10.0.0.1$(id):51820", goodIP},
		{"endpoint no port", goodKey, "10.0.0.1", goodIP},
		{"endpoint bad port", goodKey, "10.0.0.1:70000", goodIP},
	}
	for _, tc := range bad {
		if err := validatePeerInputs(tc.pub, tc.endpoint, tc.wgIP); err == nil {
			t.Errorf("%s: expected rejection, got nil", tc.name)
		}
	}
}
