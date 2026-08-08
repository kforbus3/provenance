package overlay

import (
	"strings"
	"testing"
)

// The jump-server provisioning script must install the forwarding deny that keeps
// the overlay hub-and-spoke, and must do it idempotently and non-fatally — this
// script runs on every re-enrollment, under `set -e`, on jump hosts whose iptables
// backend Fleet does not control.
func TestJumpServerScriptInstallsPeerIsolation(t *testing.T) {
	o := New(testCfg(), nil)
	srv, err := o.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	script := o.JumpServerScript([]byte("CA\n"), []byte("CERT\n"), []byte("KEY\n"), srv)

	if !strings.Contains(script, "iptables -I FORWARD 1 -s 10.100.0.0/24 -d 10.100.0.0/24 -j DROP") {
		t.Errorf("script does not install the overlay peer-isolation deny:\n%s", script)
	}
	// -C before -I: re-enrollment must not stack a duplicate rule every run.
	if !strings.Contains(script, "iptables -C FORWARD -s 10.100.0.0/24 -d 10.100.0.0/24 -j DROP") {
		t.Error("script does not test for the rule before inserting it (would stack duplicates on re-enrollment)")
	}
	// The rule goes in before the daemon starts, so there is no window in which
	// clients are connected and can still reach each other.
	if iso, start := strings.Index(script, "PEER_ISOLATION"), strings.Index(script, "openvpn --config"); iso < 0 || start < 0 || iso > start {
		t.Error("peer isolation is applied after the OpenVPN server starts; it must precede it")
	}
	// `set -e` heads the script: an iptables failure must not abort provisioning.
	if !strings.Contains(script, "echo OVPN_PEER_ISOLATION_FAILED") {
		t.Error("iptables failure is not handled; under set -e it would abort server provisioning")
	}
}

func TestJumpServerScriptOmitsPeerIsolationWhenDisabled(t *testing.T) {
	cfg := testCfg()
	cfg.OverlayPeerIsolation = false
	o := New(cfg, nil)
	srv, err := o.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	script := o.JumpServerScript([]byte("CA\n"), []byte("CERT\n"), []byte("KEY\n"), srv)

	if strings.Contains(script, "iptables") {
		t.Errorf("isolation disabled but the script still touches iptables:\n%s", script)
	}
	if !strings.Contains(script, "openvpn --config") {
		t.Error("disabling isolation must not affect the rest of provisioning")
	}
}

// The subnet reaches a shell command line, so it is re-parsed rather than
// interpolated: a configured subnet in host form must be emitted in network form,
// and anything unparseable must produce no rule at all rather than a broken one.
func TestPeerIsolationNormalizesSubnet(t *testing.T) {
	cfg := testCfg()
	cfg.WGSubnet = "10.100.0.7/24"
	if got := New(cfg, nil).peerIsolationScript(); !strings.Contains(got, "-s 10.100.0.0/24 -d 10.100.0.0/24") {
		t.Errorf("subnet not normalized to network form: %q", got)
	}

	cfg.WGSubnet = "not a subnet; rm -rf /"
	if got := New(cfg, nil).peerIsolationScript(); got != "" {
		t.Errorf("unparseable subnet produced a rule: %q", got)
	}
}
