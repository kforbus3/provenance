package overlay

import (
	"os/exec"
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
	script := o.JumpServerScript([]byte("CA\n"), []byte("CERT\n"), []byte("KEY\n"), []byte(testCRLPEM), srv)

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
	script := o.JumpServerScript([]byte("CA\n"), []byte("CERT\n"), []byte("KEY\n"), []byte(testCRLPEM), srv)

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
	// The jump-side deny is scoped to the OpenVPN overlay's OWN subnet — the two
	// overlays are separate address plans, and each isolates the one it serves.
	cfg.OVPNSubnet = "10.101.0.7/24"
	if got := New(cfg, nil).peerIsolationScript(); !strings.Contains(got, "-s 10.101.0.0/24 -d 10.101.0.0/24") {
		t.Errorf("subnet not normalized to network form: %q", got)
	}

	cfg.OVPNSubnet = "not a subnet; rm -rf /"
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
		`iptables -I INPUT  1 -i "$dev" -j FLEET-OVPN-IN`,
		`iptables -I OUTPUT 1 -o "$dev" -j FLEET-OVPN-OUT`,
		`iptables -A FLEET-OVPN-IN  ! -s "$JUMP"/32 -j DROP`,
		`iptables -A FLEET-OVPN-OUT ! -d "$JUMP"/32 -j DROP`,
		`JUMP=10.100.0.1`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("isolation script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "10.100.0.0/24") {
		t.Error("script filters on the subnet; that also catches loopback traffic to the host's own overlay IP")
	}
	// The rules name the jump host by ADDRESS, so they have to be self-correcting:
	// moving the overlay to its own subnet changed that address, and a rule left over
	// from the old one matches everything from the new jump host — blackholing the
	// tunnel with no error anywhere. Flushing Fleet's own chains is what retires it.
	if !strings.Contains(script, `iptables -F "$_c"`) {
		t.Error("chains are not flushed; a changed jump address would leave a DROP that blackholes the overlay")
	}
	// Under script-security 2 a non-zero `up` aborts the tunnel. Failing open is the
	// deliberate choice everywhere else in peer isolation; it must hold here too.
	if !strings.Contains(script, "exit 0") {
		t.Error("script can exit non-zero, which would abort the tunnel instead of failing open")
	}
	if !strings.Contains(script, `iptables -C INPUT`) || !strings.Contains(script, `iptables -C OUTPUT`) {
		t.Error("chain hooks are not idempotent; every reconnect would stack a duplicate")
	}
}

// The script must be on disk before the tunnel starts, or the first connect races it.
func TestOpenVPNHostInstallWritesIsolationBeforeStart(t *testing.T) {
	o := New(testCfg(), nil)
	install := o.HostInstallScript([]byte("CA\n"), []byte("CERT\n"), []byte("KEY\n"), o.ClientConfig("j:1194"), "10.100.0.27")

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
	install := o.HostInstallScript([]byte("CA\n"), []byte("CERT\n"), []byte("KEY\n"), cli, "10.100.0.27")
	if strings.Contains(install, "peer-isolation") {
		t.Error("isolation disabled but the install script still writes the script")
	}
}

// OpenVPN runs the isolation script itself, as the tunnel comes up, under
// script-security 2 — where a non-zero exit ABORTS the tunnel. A syntax error here
// would therefore not just skip the filter, it would take the host off the overlay,
// and the only trace is a line in the client's log. Parse it.
func TestOpenVPNHostIsolationScriptIsPOSIXSh(t *testing.T) {
	script := New(testCfg(), nil).hostIsolationScript()
	if script == "" {
		t.Fatal("isolation script is empty with isolation enabled")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh available: %v", err)
	}
	cmd := exec.Command(sh, "-n") // parse only; never execute
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("isolation script is not valid POSIX sh: %v\n%s\n---\n%s", err, out, script)
	}
}

// The same for the whole host bring-up script, which carries the isolation script
// inside a heredoc: a quoting slip there breaks the install rather than the tunnel.
func TestOpenVPNHostInstallScriptIsPOSIXSh(t *testing.T) {
	o := New(testCfg(), nil)
	script := o.HostInstallScript([]byte("CA\n"), []byte("CERT\n"), []byte("KEY\n"), o.ClientConfig("j:1194"), "10.100.0.27")
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh available: %v", err)
	}
	cmd := exec.Command(sh, "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("host install script is not valid POSIX sh: %v\n%s", err, out)
	}
}

// Peer isolation on this overlay IS iptables — OpenVPN has no AllowedIPs, so a filter
// on the tunnel device is the only thing isolating the host at its own end. The up
// script fails open when iptables is missing (a failing up script would abort the
// tunnel under script-security 2), so a host without it joins the overlay silently
// unisolated. Enrollment therefore has to install it, and has to say so when it
// cannot — an enrollment that succeeds identically either way hides the difference.
func TestJumpServerProvidesIptablesForIsolation(t *testing.T) {
	o := New(testCfg(), nil)
	srv, err := o.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	script := o.JumpServerScript([]byte("CA\n"), []byte("CERT\n"), []byte("KEY\n"), []byte(testCRLPEM), srv)
	if !strings.Contains(script, "apt-get install -y -qq iptables") {
		t.Errorf("jump-server script does not provide iptables for its forwarding deny:\n%s", script)
	}
	// The install must precede the rule it exists for.
	if strings.Index(script, "install -y -qq iptables") > strings.Index(script, "iptables -I FORWARD 1") {
		t.Error("iptables is installed after the deny is attempted")
	}
	// Isolation off: no rule, so nothing to install for.
	cfg := testCfg()
	cfg.OverlayPeerIsolation = false
	srvOff, err := New(cfg, nil).ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	off := New(cfg, nil).JumpServerScript([]byte("CA\n"), []byte("CERT\n"), []byte("KEY\n"), []byte(testCRLPEM), srvOff)
	if strings.Contains(off, "install -y -qq iptables") {
		t.Error("installs iptables for a deny that is disabled")
	}
}

func TestHostInstallProvidesIptablesForIsolation(t *testing.T) {
	o := New(testCfg(), nil)
	script := o.HostInstallScript([]byte("CA\n"), []byte("CERT\n"), []byte("KEY\n"), o.ClientConfig("j:1194"), "10.100.0.27")

	for _, want := range []string{
		"apt-get install -y -qq iptables",
		"dnf install -y -q iptables",
		"yum install -y -q iptables",
		"apk add --no-cache iptables",
		"OVPN_IPTABLES_MISSING",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("install script does not provide iptables via %q:\n%s", want, script)
		}
	}
	// It must be in place BEFORE the tunnel starts, like the up script itself: the
	// first connect is otherwise unfiltered.
	if strings.Index(script, "iptables") > strings.Index(script, "systemctl enable --now openvpn@fleet-overlay") {
		t.Error("iptables is installed after the tunnel is started; the first connect would be unisolated")
	}

	// With isolation off there is nothing to filter with, so nothing to install.
	cfg := testCfg()
	cfg.OverlayPeerIsolation = false
	off := New(cfg, nil).HostInstallScript([]byte("CA\n"), []byte("CERT\n"), []byte("KEY\n"), cfg.WGSubnet, "10.100.0.27")
	if strings.Contains(off, "iptables") {
		t.Error("installs iptables even with peer isolation disabled")
	}
}

// A host that ends up without iptables still enrolls — but the step has to carry the
// warning, or an operator has no way to know this host is unisolated.
func TestBringupWarnsWhenIsolationCouldNotBeApplied(t *testing.T) {
	out := "OVPN_IPTABLES_MISSING\nOVPN_HOST_IP=10.101.0.27\nOVPN_HOST_CONFIGURED\n"
	detail, err := checkHostBringup(out, "10.101.0.27")
	if err != nil {
		t.Fatalf("a missing filter must not fail the enrollment: %v", err)
	}
	if !strings.Contains(detail, "peer isolation is NOT applied") {
		t.Errorf("detail does not report the unisolated host: %q", detail)
	}

	clean, err := checkHostBringup("OVPN_HOST_IP=10.101.0.27\nOVPN_HOST_CONFIGURED\n", "10.101.0.27")
	if err != nil || strings.Contains(clean, "WARNING") {
		t.Errorf("warned about isolation on a host that has it: %q (%v)", clean, err)
	}
}

// Writing the up script is not the same as running it. openvpn only runs it when a
// tunnel comes UP, and a re-enrollment usually finds the client already running — the
// unit is enabled and active, so starting it is a no-op. A host that first connected
// without iptables therefore stayed unisolated through every later enrollment, with
// the script sitting on disk unused. Enrollment has to apply it itself.
func TestHostInstallAppliesIsolationRatherThanOnlyWritingIt(t *testing.T) {
	o := New(testCfg(), nil)
	script := o.HostInstallScript([]byte("CA\n"), []byte("CERT\n"), []byte("KEY\n"), o.ClientConfig("j:1194"), "10.100.0.27")

	// Run the up script directly, with $dev set to the device that actually holds the
	// assigned address — openvpn's own contract for that variable.
	if !strings.Contains(script, `dev="$OVPN_DEV" /etc/openvpn/fleet/peer-isolation.sh`) {
		t.Errorf("install script never runs the isolation script itself:\n%s", script)
	}
	// And report what is in place afterwards, since the script fails open: a clean run
	// and an unisolated host are otherwise indistinguishable.
	for _, want := range []string{"OVPN_ISOLATION_OK", "OVPN_ISOLATION_MISSING", "iptables -S FLEET-OVPN-IN"} {
		if !strings.Contains(script, want) {
			t.Errorf("install script does not verify isolation (%q missing)", want)
		}
	}
	// It must come after the tunnel is confirmed, or there is no device to filter.
	if strings.Index(script, "peer-isolation.sh >/dev/null") < strings.Index(script, "OVPN_HOST_IP=$OVPN_IP") {
		t.Error("isolation is applied before the tunnel address is known")
	}

	cfg := testCfg()
	cfg.OverlayPeerIsolation = false
	off := New(cfg, nil).HostInstallScript([]byte("CA\n"), []byte("CERT\n"), []byte("KEY\n"), cfg.WGSubnet, "10.100.0.27")
	if strings.Contains(off, "peer-isolation.sh") || strings.Contains(off, "OVPN_ISOLATION_") {
		t.Error("applies isolation that is disabled")
	}
}
