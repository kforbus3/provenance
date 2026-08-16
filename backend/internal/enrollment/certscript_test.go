package enrollment

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kforbus3/Moorgate/backend/internal/config"
	"github.com/kforbus3/Moorgate/backend/internal/models"
	"github.com/kforbus3/Moorgate/backend/internal/overlay"
)

func certTestService() *Service {
	return &Service{cfg: &config.Config{
		WGSubnet: "10.9.0.0/24", WGJumpIP: "10.9.0.1", WGPort: 51820, WGInterface: "wgfleet",
	}}
}

func certTestScript(t *testing.T, retireWG bool) string {
	t.Helper()
	return certTestService().certBootstrapScript(
		"fleet", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI-ca fleet-ca",
		"10.9.0.5", "", uuid.MustParse("abcdef01-2345-6789-abcd-ef0123456789"),
		"openvpn",
		overlay.HostBringup{Script: "set -e\necho OVPN_HOST_CONFIGURED", Marker: "OVPN_HOST_CONFIGURED"},
		retireWG,
	)
}

// Picking OpenVPN in the enrollment dialog and getting a WireGuard host back is the
// bug this flow shipped with: the no-install path had one script builder and it was
// WireGuard's. A cert-overlay script must join the overlay it was asked for and must
// not install WireGuard on the way.
func TestCertBootstrapScriptJoinsTheCertOverlayNotWireGuard(t *testing.T) {
	script := certTestScript(t, false)

	if !strings.Contains(script, "joining the openvpn overlay") {
		t.Error("script does not run an openvpn phase")
	}
	if !strings.Contains(script, "OVPN_HOST_CONFIGURED") {
		t.Error("script does not check the overlay's success marker")
	}
	if strings.Contains(script, "wg genkey") || strings.Contains(script, "wg-quick up") {
		t.Error("cert-overlay script still brings up a WireGuard interface")
	}
	// The operator has no key to paste under a cert overlay — the tunnel is
	// authenticated by the certificate embedded in the script. Telling them to copy a
	// key that is never printed is how this flow strands an enrollment half-finished.
	if strings.Contains(script, "HOST PUBLIC KEY") {
		t.Error("cert-overlay script asks the operator for a host public key")
	}
}

// The script is generated and piped by hand, so a bashism only surfaces on a
// dash/ash host at enrollment time.
func TestCertBootstrapScriptIsPOSIXSh(t *testing.T) {
	for _, retire := range []bool{false, true} {
		script := certTestScript(t, retire)
		if !strings.HasPrefix(script, "#!/bin/sh\n") {
			t.Fatalf("script must declare #!/bin/sh, got %q", strings.SplitN(script, "\n", 2)[0])
		}
		sh, err := exec.LookPath("sh")
		if err != nil {
			t.Skipf("no sh available: %v", err)
		}
		cmd := exec.Command(sh, "-n") // parse only; never execute
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("generated script (retireWG=%v) is not valid POSIX sh: %v\n%s\n---\n%s", retire, err, out, script)
		}
	}
}

// Phase numbering is the operator's only progress indicator while the script runs.
// It is built from a count of the phases actually emitted, so an optional phase must
// renumber the rest rather than leaving a gap or a second "3/4".
func TestCertBootstrapScriptNumbersEveryPhase(t *testing.T) {
	for _, tc := range []struct {
		name     string
		retireWG bool
		krl      string
		want     []string
	}{
		{"minimal", false, "", []string{"[fleet] 1/2", "[fleet] 2/2"}},
		{"retire + revocation", true, "a2Vlbg==", []string{"[fleet] 1/4", "[fleet] 2/4", "[fleet] 3/4", "[fleet] 4/4"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := certTestService().certBootstrapScript(
				"fleet", "ssh-ed25519 AAAA-ca fleet-ca", "10.9.0.5", tc.krl,
				uuid.New(), "openvpn",
				overlay.HostBringup{Script: "echo OVPN_HOST_CONFIGURED", Marker: "OVPN_HOST_CONFIGURED"},
				tc.retireWG,
			)
			for _, want := range tc.want {
				if !strings.Contains(script, want) {
					t.Errorf("missing phase %q in:\n%s", want, script)
				}
			}
			if strings.Contains(script, "[fleet] 5/") {
				t.Error("emitted more phases than it counted")
			}
		})
	}
}

// A host switching from WireGuard to OpenVPN keeps the SAME overlay address, so both
// interfaces would claim it and which one answers comes down to route metrics. The
// switch is only complete if the old interface is retired.
func TestCertBootstrapScriptRetiresWireGuardWhenSwitching(t *testing.T) {
	switching := certTestScript(t, true)
	if !strings.Contains(switching, "retiring the WireGuard overlay") {
		t.Error("switching host is not told to retire its WireGuard interface")
	}
	if !strings.Contains(switching, "wg-quick down $IF") {
		t.Error("teardown does not bring the interface down")
	}
	if !strings.Contains(switching, "systemctl disable --now wg-quick@$IF") {
		t.Error("teardown leaves WireGuard enabled on boot — it returns after a reboot")
	}

	// A host that never had WireGuard has nothing to retire; running the teardown
	// anyway would report a phase failure for a no-op.
	fresh := certTestScript(t, false)
	if strings.Contains(fresh, "retiring the WireGuard overlay") {
		t.Error("fresh host runs a WireGuard teardown it does not need")
	}
}

func TestHadWireGuard(t *testing.T) {
	for _, tc := range []struct {
		name      string
		host      models.Host
		wantHad   bool
		wantAnyWG bool
	}{
		{"fresh host", models.Host{}, false, false},
		{"enrolled on wireguard", models.Host{Enrolled: true, Overlay: "wireguard"}, true, true},
		// Enrolled before per-host overlays existed: an empty overlay is WireGuard.
		{"enrolled before overlays existed", models.Host{Enrolled: true}, true, true},
		{"address assigned, enrollment unfinished", models.Host{WGAddress: "10.9.0.5"}, true, true},
		// The over-SSH path skips a host already on OpenVPN — its previous run tore
		// WireGuard down. The no-install path can't: generating the script is what
		// stamps the host as openvpn, so this same host may still be running WireGuard
		// and a second generation must still carry the teardown.
		{"already on openvpn", models.Host{Enrolled: true, Overlay: "openvpn", WGAddress: "10.9.0.5"}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hadWireGuard(&tc.host); got != tc.wantHad {
				t.Errorf("hadWireGuard = %v, want %v", got, tc.wantHad)
			}
			if got := hasOverlayState(&tc.host); got != tc.wantAnyWG {
				t.Errorf("hasOverlayState = %v, want %v", got, tc.wantAnyWG)
			}
		})
	}
}

// The teardown renames the config instead of deleting it, and leaves the private key,
// so a host moved back to WireGuard still has its identity and the operator can see
// what was retired.
func TestWGTeardownPreservesTheOldConfig(t *testing.T) {
	script := certTestService().wgTeardownScript()
	if !strings.Contains(script, "/etc/wireguard/$IF.conf.fleet-disabled") {
		t.Error("teardown does not preserve the retired config")
	}
	if strings.Contains(script, "rm -f /etc/wireguard") {
		t.Error("teardown deletes WireGuard state instead of retiring it")
	}
	if !strings.HasPrefix(script, "set +e") {
		t.Error("teardown must be best-effort: a host with no WireGuard to retire is not a failure")
	}
}
