package overlay

import (
	"context"
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

	var ran string
	detail, err := o.RetireJump(context.Background(), id, func(script string) (string, error) {
		ran = script
		return "OVPN_CCD_REMOVED\n", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ran, "ccd/"+ClientCN(id.String())) {
		t.Errorf("script does not target this host's ccd entry:\n%s", ran)
	}
	if detail == "" {
		t.Error("a removal that happened should be reported to the step log")
	}

	// Absent is not an error: retiring is idempotent, and a host that was never on
	// this overlay must not fail a re-enrollment.
	detail, err = o.RetireJump(context.Background(), id, func(string) (string, error) {
		return "OVPN_CCD_ABSENT\n", nil
	})
	if err != nil || detail != "" {
		t.Errorf("absent pin reported as detail=%q err=%v; want a silent no-op", detail, err)
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
