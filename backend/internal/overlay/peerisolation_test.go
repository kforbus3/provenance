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

// OpenVPN has no AllowedIPs, so the host end is a firewall script OpenVPN runs as
// the tunnel comes up. Without it an OpenVPN deployment's isolation is one rule on
// the jump host, which fails open.
func TestOpenVPNClientConfigHooksHostIsolation(t *testing.T) {
	o := New(testCfg(), nil)
	cli := o.ClientConfig("jump.example.com:1194")

	// script-security 2 is required for OpenVPN to run `up` at all — without it the
	// hook is inert and the host silently has no filter.
	if !strings.Contains(cli, "script-security 2") {
		t.Error("client config lacks script-security 2; the up script would never run")
	}
	if !strings.Contains(cli, "up /etc/openvpn/fleet/peer-isolation.sh") {
		t.Errorf("client config does not reference the isolation script:\n%s", cli)
	}
}

func TestOpenVPNHostIsolationScript(t *testing.T) {
	script := New(testCfg(), nil).hostIsolationScript()

	// Scoped to the tunnel device, NOT the overlay subnet: a subnet-scoped rule also
	// matches the host reaching its own overlay address over loopback.
	for _, want := range []string{
		`iptables -I INPUT  1 -i "$dev" ! -s "$JUMP"/32 -j DROP`,
		`iptables -I OUTPUT 1 -o "$dev" ! -d "$JUMP"/32 -j DROP`,
		`JUMP=10.100.0.1`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("isolation script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "10.100.0.0/24") {
		t.Error("script filters on the subnet; that also catches loopback traffic to the host's own overlay IP")
	}
	// Under script-security 2 a non-zero `up` aborts the tunnel. Failing open is the
	// deliberate choice everywhere else in peer isolation; it must hold here too.
	if !strings.Contains(script, "exit 0") {
		t.Error("script can exit non-zero, which would abort the tunnel instead of failing open")
	}
	if !strings.Contains(script, `iptables -C INPUT`) || !strings.Contains(script, `iptables -C OUTPUT`) {
		t.Error("rules are not idempotent; every reconnect would stack a duplicate")
	}
}

// The script must be on disk before the tunnel starts, or the first connect races it.
func TestOpenVPNHostInstallWritesIsolationBeforeStart(t *testing.T) {
	o := New(testCfg(), nil)
	install := o.HostInstallScript([]byte("CA\n"), []byte("CERT\n"), []byte("KEY\n"), o.ClientConfig("j:1194"))

	wrote := strings.Index(install, "peer-isolation.sh <<")
	started := strings.Index(install, "systemctl enable --now")
	if wrote < 0 {
		t.Fatalf("install script never writes peer-isolation.sh:\n%s", install)
	}
	if started >= 0 && wrote > started {
		t.Error("isolation script is written after the tunnel starts; first connect would be unfiltered")
	}
	if !strings.Contains(install, "chmod 0700 /etc/openvpn/fleet/peer-isolation.sh") {
		t.Error("isolation script is not mode 0700 (it runs as root)")
	}
}

func TestOpenVPNHostIsolationOmittedWhenDisabled(t *testing.T) {
	cfg := testCfg()
	cfg.OverlayPeerIsolation = false
	o := New(cfg, nil)

	if got := o.hostIsolationScript(); got != "" {
		t.Errorf("isolation disabled but a script was rendered: %q", got)
	}
	cli := o.ClientConfig("jump.example.com:1194")
	if strings.Contains(cli, "script-security") || strings.Contains(cli, "peer-isolation") {
		t.Errorf("isolation disabled but the client config still hooks it:\n%s", cli)
	}
	install := o.HostInstallScript([]byte("CA\n"), []byte("CERT\n"), []byte("KEY\n"), cli)
	if strings.Contains(install, "peer-isolation") {
		t.Error("isolation disabled but the install script still writes the script")
	}
}
