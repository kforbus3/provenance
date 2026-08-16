package overlay

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Moving a host back to WireGuard has to stop the OpenVPN client, not just stop
// pointing at it. A client left running reconnects to an overlay the host has left,
// and the host ends up with two interfaces racing for its traffic — the same failure
// the separate subnets exist to prevent, arriving from the other direction.
func TestRetireHostScriptStopsAndDisablesTheClient(t *testing.T) {
	hb := startTestOverlay().RetireHostScript()

	for _, want := range []string{
		"systemctl disable --now openvpn@fleet-overlay",
		"systemctl disable --now openvpn-client@fleet-overlay",
		"pgrep -x openvpn",
		"OVPN_RETIRED",
	} {
		if !strings.Contains(hb.Script, want) {
			t.Errorf("retire script missing %q:\n%s", want, hb.Script)
		}
	}
	// Same hazard as the start guard: `pgrep -f` here would match this script's own
	// shell (its text contains the config path) and kill nothing while reporting a
	// clean retirement.
	if strings.Contains(hb.Script, "pgrep -f") {
		t.Error("retire script matches on command line, which also matches its own shell")
	}
	if !strings.HasPrefix(hb.Script, "set +e") {
		t.Error("retire script is not best-effort: a host with no client to stop is not a failure")
	}
	// The peer-isolation rules go with it. They are scoped to the tunnel device, so
	// once that device is gone they match nothing — but tun0 is a name the kernel
	// reuses, and the next VPN this host runs would inherit a DROP naming a jump host
	// it has never heard of.
	for _, want := range []string{
		`iptables -D "$_chain" $_rule`,
		`iptables -F "$_own"`,
		`iptables -X "$_own"`,
		"FLEET-OVPN-IN",
		"FLEET-OVPN-OUT",
	} {
		if !strings.Contains(hb.Script, want) {
			t.Errorf("retire script leaves the isolation rules behind (%q missing):\n%s", want, hb.Script)
		}
	}

	// The client certificate stays valid — the host was moved, not revoked — but the
	// config is set aside so nothing restarts it.
	if !strings.Contains(hb.Script, "client.ovpn.fleet-disabled") {
		t.Error("retire script does not set the client config aside")
	}
	if strings.Contains(hb.Script, "rm -f /etc/openvpn/fleet/client.key") {
		t.Error("retire script deletes the host's issued key material")
	}
	if hb.Marker == "" || !strings.Contains(hb.Script, hb.Marker) {
		t.Errorf("marker %q is not printed by the script", hb.Marker)
	}

	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh: %v", err)
	}
	cmd := exec.Command(sh, "-n")
	cmd.Stdin = strings.NewReader(hb.Script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("retire script is not valid POSIX sh: %v\n%s", err, out)
	}
}

// The hub half: the pinned address has to go, or the server keeps answering for a
// host that has left and the address cannot be safely reissued.
func TestRetireJumpRemovesThePinnedAddress(t *testing.T) {
	o := startTestOverlay()
	id := uuid.MustParse("cd9aabde-6a7f-47fc-992a-42de959a9b5c")

	// The jump runner sees two scripts now — the ccd removal and the CRL push — so it
	// answers each with its own marker rather than one blanket reply.
	jump := func(ccdReply string) (func(string) (string, error), *[]string) {
		var ran []string
		return func(script string) (string, error) {
			ran = append(ran, script)
			if strings.Contains(script, "crl.pem") {
				return "OVPN_CRL_UPDATED\n", nil
			}
			return ccdReply + "\n", nil
		}, &ran
	}

	run, ran := jump("OVPN_CCD_REMOVED")
	detail, err := o.RetireJump(context.Background(), id, run)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(*ran, "\n")
	if !strings.Contains(all, "ccd/"+ClientCN(id.String())) {
		t.Errorf("script does not target this host's ccd entry:\n%s", all)
	}
	if detail == "" {
		t.Error("a removal that happened should be reported to the step log")
	}

	// Removing the ccd pin only takes the host's STATIC address away — the server
	// still authenticates any certificate the CA signed. Publishing the revocation
	// list is what actually stops a retired host reconnecting, so it is part of
	// retiring, not an optional extra.
	if !strings.Contains(all, "crl.pem") {
		t.Errorf("retiring a host did not publish the revocation list:\n%s", all)
	}
	if !strings.Contains(detail, "revocation list") {
		t.Errorf("the step log should say the revocation list was published, got %q", detail)
	}

	// Absent is not an error: retiring is idempotent, and a host that was never on
	// this overlay must not fail a re-enrollment. The CRL still goes out.
	run, ran = jump("OVPN_CCD_ABSENT")
	detail, err = o.RetireJump(context.Background(), id, run)
	if err != nil {
		t.Errorf("absent pin must not fail: %v", err)
	}
	if !strings.Contains(strings.Join(*ran, "\n"), "crl.pem") {
		t.Error("the revocation list must be published even when there was no pin to remove")
	}
	if !strings.Contains(detail, "revocation list") {
		t.Errorf("the idempotent retire should still report the revocation list was published, got %q", detail)
	}

	// A CRL that cannot be published is an ERROR, not a detail line. Reporting
	// success here would tell the operator a host was cut off when it was not.
	failing := &OpenVPN{cfg: o.cfg, pki: stubCA{crlErr: errors.New("no CA")}}
	if _, err := failing.RetireJump(context.Background(), id, func(string) (string, error) {
		return "OVPN_CCD_REMOVED\n", nil
	}); err == nil {
		t.Error("a CRL that could not be built must fail the retire, not pass quietly")
	}
}

// A host whose client starts but never gets an address produces no useful client
// log — the packets are simply not arriving. The error therefore has to carry the
// endpoint that was dialled and what to check, or the operator has nowhere to start.
func TestNoTunnelErrorNamesTheEndpointAndWhatToCheck(t *testing.T) {
	out := "OVPN_HOST_NO_TUNNEL\nOVPN_REMOTE=vpn.example.com:1194\n--- openvpn client log ---\n"
	_, err := checkHostBringup(out, "10.101.0.27")
	if err == nil {
		t.Fatal("a host with no tunnel was accepted")
	}
	for _, want := range []string{
		"vpn.example.com:1194", // the endpoint that did not answer
		"published by the jump host",
		"make up-single", // the reason a redeploy does not fix it
		"hairpin",        // the LAN-host case
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%s", want, err)
		}
	}

	// No endpoint reported: still an error, just without the "at <addr>" clause.
	_, err = checkHostBringup("OVPN_HOST_NO_TUNNEL\nOVPN_REMOTE=\n", "10.101.0.27")
	if err == nil || strings.Contains(err.Error(), " at ") {
		t.Errorf("missing endpoint should be omitted, not rendered empty: %v", err)
	}
}

// testCRLPEM is a stand-in revocation list for scripts that only need SOME CRL bytes.
const testCRLPEM = "-----BEGIN X509 CRL-----\ntest\n-----END X509 CRL-----\n"

// THE BUG THIS PINS DOWN: teardown reused RetireHostScript, which renames
// client.ovpn to .fleet-disabled and deliberately KEEPS ca.crt/client.crt/client.key.
// The renamed file is a complete, working config that references those keys by
// absolute path, so a decommissioned host could be put straight back on the overlay
// by moving it back — or by pointing openvpn at it where it lay.
func TestPurgeDestroysTheClientMaterialRetireKeeps(t *testing.T) {
	o := startTestOverlay()
	retire := o.RetireHostScript().Script
	purge := o.PurgeHostScript().Script

	// The material that makes the leftover config work. Retiring keeps it on purpose
	// (a host switched away and back re-uses its certificate); purging must not.
	for _, f := range []string{"/ca.crt", "/client.crt", "/client.key"} {
		if strings.Contains(retire, "rm -f") && strings.Contains(retireRemovals(retire), f) {
			t.Errorf("retire should KEEP %s for a transport switch", f)
		}
		if !strings.Contains(purge, f) {
			t.Errorf("purge leaves %s on a decommissioned host", f)
		}
	}
	// The renamed config is the thing that actually reconnects; it has to go too, not
	// just the live one.
	if !strings.Contains(purge, "client.ovpn.fleet-disabled") {
		t.Error("purge leaves the renamed client.ovpn, which is a complete working config")
	}
	// Purging is a superset of retiring: the client still has to be stopped and kept
	// from restarting, or the files go while a daemon holds the tunnel open.
	if !strings.Contains(purge, "systemctl disable --now openvpn") {
		t.Error("purge must still stop and disable the client")
	}
	if !strings.HasPrefix(purge, retire) {
		t.Error("purge should build on the retire script rather than reimplement it")
	}

	// Bounded to Fleet's own directory — no globbing that could take an operator's
	// other openvpn configuration with it.
	if strings.Contains(purge, "rm -rf") {
		t.Error("purge should remove named files, not recurse")
	}
	for _, forbidden := range []string{"/etc/openvpn/*", "/etc/openvpn/server", "/etc/ssl", "/etc/pki"} {
		if strings.Contains(purge, forbidden) {
			t.Errorf("purge reaches outside Fleet's directory: %q", forbidden)
		}
	}

	if sh, err := exec.LookPath("sh"); err == nil {
		cmd := exec.Command(sh, "-n")
		cmd.Stdin = strings.NewReader(purge)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("purge script is not valid POSIX sh: %v\n%s", err, out)
		}
	}
}

// retireRemovals returns just the rm lines of a script, so a path merely MENTIONED
// (e.g. in a pgrep match) is not mistaken for one being deleted.
func retireRemovals(script string) string {
	var b strings.Builder
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "rm ") {
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// The server must actually consult the revocation list. Without crl-verify the CRL
// is a file nobody reads, and every certificate the CA ever signed stays valid
// forever — which is what let a decommissioned host reconnect.
func TestServerConfigVerifiesTheCRL(t *testing.T) {
	o := startTestOverlay()
	conf, err := o.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "crl-verify "+fleetDir+"/crl.pem") {
		t.Errorf("server config does not verify the revocation list:\n%s", conf)
	}

	// openvpn refuses to start when crl-verify names a missing file, so the list has
	// to be written BEFORE the config that references it.
	script := o.JumpServerScript([]byte("ca"), []byte("crt"), []byte("key"), []byte(testCRLPEM), conf)
	crlAt := strings.Index(script, "/crl.pem <<")
	confAt := strings.Index(script, "/server.conf <<")
	if crlAt < 0 {
		t.Fatalf("jump script never writes the CRL:\n%s", script)
	}
	if confAt < 0 || crlAt > confAt {
		t.Error("the CRL must be written before the server config that names it, or openvpn will not start")
	}
}
