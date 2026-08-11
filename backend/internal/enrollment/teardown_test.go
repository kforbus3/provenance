package enrollment

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/overlay"
)

func teardownScript(t *testing.T, loginUser string) string {
	t.Helper()
	svc := &Service{cfg: &config.Config{WGInterface: "wgfleet"}}
	return svc.hostTeardownScript(loginUser, svc.hostOverlayRetireScript(&models.Host{}))
}

// The teardown deletes the very account its SSH session is running as. userdel
// refuses while a process of that user is alive, so a foreground run would strip the
// sudoers grant and the CA trust, then fail on both accounts — leaving a host that
// is half torn down and no longer reachable to finish the job. The work therefore
// has to be detached from the session and outlive it.
func TestTeardownDetachesFromTheSSHSession(t *testing.T) {
	s := teardownScript(t, "fleet")

	if !strings.Contains(s, "setsid nohup /usr/local/sbin/fleet-unenroll.sh") {
		t.Error("teardown must launch detached (setsid nohup), or userdel cannot remove the account it is running as")
	}
	if !strings.Contains(s, "< /dev/null") {
		t.Error("detached launch must close stdin, or the SSH session will not return")
	}
	if !strings.Contains(s, "sleep 8") {
		t.Error("the detached script must wait for the launching session to close before userdel")
	}
	// The outer command has to come back promptly with a definite marker; the caller
	// treats its absence as a failed teardown.
	if !strings.Contains(s, "echo TEARDOWN_STARTED") {
		t.Error("teardown must report a start marker the caller can check")
	}
	// userdel only succeeds once nothing is running as the account.
	if !strings.Contains(s, `pkill -KILL -u "$U"`) {
		t.Error("teardown must kill the account's processes before userdel")
	}
}

// Everything enrollment installs has to come off, or deleting a host leaves a
// standing NOPASSWD root account and a trusted CA on a machine Fleet no longer
// manages or audits — which is the whole point of the teardown.
func TestTeardownRemovesEverythingEnrollmentInstalled(t *testing.T) {
	s := teardownScript(t, "fleet")

	// Cross-check against what caTrustScript actually writes, so a path added there
	// and forgotten here shows up as a failure rather than as a leftover on a host.
	install := (&Service{cfg: &config.Config{}}).caTrustScript("fleet", "ca-key", uuid.Nil)
	for _, path := range []string{
		"/etc/sudoers.d/fleet",
		"/etc/ssh/fleet_ca.pub",
		"/etc/ssh/auth_principals",
		"/etc/ssh/sshd_config.d/00-fleet.conf",
	} {
		if !strings.Contains(install, path) {
			t.Fatalf("test is stale: caTrustScript no longer writes %s", path)
		}
		if !strings.Contains(s, path) {
			t.Errorf("teardown leaves %s behind", path)
		}
	}
	// Not written by caTrustScript, but pushed to every host by KRL distribution.
	if !strings.Contains(s, "/etc/ssh/fleet_krl") {
		t.Error("teardown leaves the revocation list behind")
	}
	// Both accounts, not just the privileged one.
	if !strings.Contains(s, `NOSUDO="${LOGIN}-login"`) {
		t.Error("teardown must remove the login-only account as well as the privileged one")
	}
	if !strings.Contains(s, `for U in "$LOGIN" "$NOSUDO"`) {
		t.Error("teardown must iterate both accounts")
	}
}

// A cleanup that cuts the operator off from the host is worse than the leftovers it
// removes. It must touch only what Fleet wrote, and must not reload sshd into a
// configuration that no longer parses.
func TestTeardownDoesNotStrandTheHost(t *testing.T) {
	s := teardownScript(t, "fleet")

	for _, forbidden := range []string{"authorized_keys", "/root", "PermitRootLogin", "/etc/passwd", "/etc/shadow"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("teardown touches %q, which Fleet did not install", forbidden)
		}
	}
	// The sudoers removal must be the single file Fleet wrote, never the directory
	// or the main file.
	if strings.Contains(s, "rm -f /etc/sudoers ") || strings.Contains(s, "rm -rf /etc/sudoers.d") {
		t.Error("teardown must remove only /etc/sudoers.d/fleet")
	}
	if !strings.Contains(s, "sshd -t") {
		t.Error("teardown must validate the remaining sshd config before reloading")
	}
	// The reload has to be gated on that validation, and a failed validation has to
	// put the operator's file back.
	validate := strings.Index(s, "if sshd -t")
	reload := strings.Index(s, "systemctl reload sshd")
	if validate < 0 || reload < 0 || validate > reload {
		t.Error("sshd reload must be guarded by a successful sshd -t")
	}
	if !strings.Contains(s, "mv -f /etc/ssh/sshd_config.fleet-backup /etc/ssh/sshd_config") {
		t.Error("a failed sshd -t must restore the operator's sshd_config")
	}
}

// The account name comes from the host record (default "fleet", but configurable),
// and both the privileged and login-only names derive from it. A teardown that
// hardcoded "fleet" would silently leave a differently-named host fully provisioned.
func TestTeardownUsesTheHostsSSHUser(t *testing.T) {
	s := teardownScript(t, "ops")
	if !strings.Contains(s, "LOGIN='ops'") {
		t.Errorf("teardown must target the host's SSH user, got:\n%s", s)
	}
	if strings.Contains(s, "LOGIN='fleet'") {
		t.Error("teardown hardcoded the default account name")
	}
}

// The script is assembled with fmt.Sprintf around a heredoc containing its own
// quoting and %-escapes — an easy place to emit something that only fails on the
// host, after the account is already gone. Parse both the outer command and the
// inner script with a real shell.
func TestTeardownScriptIsValidShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh available")
	}
	outer := teardownScript(t, "fleet")

	dir := t.TempDir()
	outerPath := filepath.Join(dir, "outer.sh")
	if err := os.WriteFile(outerPath, []byte(outer), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(sh, "-n", outerPath).CombinedOutput(); err != nil {
		t.Fatalf("outer teardown command is not valid shell: %v\n%s", err, out)
	}

	// The inner script reaches the host as heredoc content, so parse it on its own —
	// a syntax error there would not show up in the outer parse.
	start := strings.Index(outer, "#!/bin/sh")
	end := strings.Index(outer, "\nFLEETEOF")
	if start < 0 || end < 0 || end < start {
		t.Fatal("could not locate the inner script between its heredoc markers")
	}
	innerPath := filepath.Join(dir, "inner.sh")
	if err := os.WriteFile(innerPath, []byte(outer[start:end]), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(sh, "-n", innerPath).CombinedOutput(); err != nil {
		t.Fatalf("inner teardown script is not valid shell: %v\n%s", err, out)
	}

	// The date format is passed through fmt.Sprintf, where a single % would be
	// consumed as a verb and silently corrupt the timestamp.
	if strings.Contains(outer, "%%") {
		t.Error("a %% escape survived into the emitted script; it should be a literal %")
	}
	if !strings.Contains(outer, "+%Y-%m-%dT%H:%M:%SZ") {
		t.Error("the log timestamp format did not survive Sprintf intact")
	}
}

// The awk that strips Fleet's appended sshd_config block must remove exactly that
// block: the marker and the three directives Fleet wrote under it, stopping at the
// first line it did not write. Run it against a config shaped like a real one,
// including a PubkeyAuthentication the operator set themselves.
func TestTeardownStripsOnlyFleetsSSHDBlock(t *testing.T) {
	awkBin, err := exec.LookPath("awk")
	if err != nil {
		t.Skip("no awk available")
	}
	script := teardownScript(t, "fleet")
	start := strings.Index(script, "awk '")
	end := strings.Index(script[start:], "' /etc/ssh/sshd_config.fleet-backup")
	if start < 0 || end < 0 {
		t.Fatal("could not extract the sshd_config awk program from the teardown script")
	}
	prog := script[start+len("awk '") : start+end]

	const in = `# My sshd config
Port 22
PubkeyAuthentication yes
PermitRootLogin no
AuthorizedKeysFile .ssh/authorized_keys

# Fleet Terminal
PubkeyAuthentication yes
TrustedUserCAKeys /etc/ssh/fleet_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
# added by the operator afterwards
TrustedUserCAKeys /etc/ssh/other_ca.pub
`
	cmd := exec.Command(awkBin, prog)
	cmd.Stdin = strings.NewReader(in)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("awk program failed: %v", err)
	}
	got := string(out)

	if strings.Contains(got, "# Fleet Terminal") || strings.Contains(got, "/etc/ssh/fleet_ca.pub") {
		t.Errorf("Fleet's block survived:\n%s", got)
	}
	// The operator's own settings — including a PubkeyAuthentication identical to
	// the one in Fleet's block, and a CA line placed after it — must all remain.
	for _, want := range []string{
		"Port 22", "PermitRootLogin no", "AuthorizedKeysFile .ssh/authorized_keys",
		"PubkeyAuthentication yes", "# added by the operator afterwards",
		"TrustedUserCAKeys /etc/ssh/other_ca.pub",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the operator's %q was removed:\n%s", want, got)
		}
	}
	// A config with no Fleet block must come back byte-identical.
	const untouched = "Port 22\nPubkeyAuthentication yes\n"
	cmd = exec.Command(awkBin, prog)
	cmd.Stdin = strings.NewReader(untouched)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	if out, err = cmd.Output(); err != nil {
		t.Fatalf("awk program failed: %v", err)
	}
	if string(out) != untouched {
		t.Errorf("a config with no Fleet block was modified:\ngot  %q\nwant %q", out, untouched)
	}
}

// THE BUG THIS PINS DOWN: the first cut of the teardown removed the accounts, the
// sudoers grant and the CA trust, and left the overlay client running. The host was
// deleted from Fleet and kept a live, handshaking tunnel onto the fleet's network,
// with nothing left on it that Fleet managed or audited — while the documentation
// and the manual script both said the transport was retired.
func TestTeardownRetiresTheOverlay(t *testing.T) {
	wgSvc := &Service{cfg: &config.Config{WGInterface: "wgfleet"}}

	// WireGuard (the default; Overlay is "" or "wireguard").
	for _, name := range []string{"", "wireguard"} {
		script := wgSvc.hostTeardownScript("fleet", wgSvc.hostOverlayRetireScript(&models.Host{Overlay: name}))
		for _, want := range []string{
			"wg-quick down $IF",       // bring the tunnel down now
			"wg-quick@$IF",            // and keep it from coming back at boot
			"ip link delete $IF",      // remove the interface
			"/etc/wireguard/$IF.conf", // set the config aside
		} {
			if !strings.Contains(script, want) {
				t.Errorf("overlay %q: teardown leaves the tunnel up, missing %q", name, want)
			}
		}
		if !strings.Contains(script, "IF=wgfleet") {
			t.Errorf("overlay %q: teardown must target the configured interface", name)
		}
	}

	// A certificate overlay uses its provisioner's host-side retire script instead.
	certSvc := &Service{
		cfg:      &config.Config{WGInterface: "wgfleet"},
		overlays: map[string]overlay.Overlay{"openvpn": stubOverlay{retire: "echo RETIRED_OPENVPN"}},
	}
	certScript := certSvc.hostTeardownScript("fleet", certSvc.hostOverlayRetireScript(&models.Host{Overlay: "openvpn"}))
	if !strings.Contains(certScript, "echo RETIRED_OPENVPN") {
		t.Error("a cert-overlay host must get its overlay's retire script, not WireGuard's")
	}
	if strings.Contains(certScript, "wg-quick down") {
		t.Error("a cert-overlay host must not get the WireGuard teardown")
	}

	// An overlay this deployment cannot provision must say so in the teardown log
	// rather than quietly leaving a running client behind.
	orphan := (&Service{cfg: &config.Config{}}).hostOverlayRetireScript(&models.Host{Overlay: "openvpn"})
	if !strings.Contains(orphan, "STILL RUNNING") {
		t.Errorf("an unavailable overlay must warn loudly, got %q", orphan)
	}
}

// The in-app teardown and scripts/fleet-unenroll.sh remove the same things by two
// entirely separate implementations, and they drifted the moment one of them was
// written: the manual script retired WireGuard from the start, the in-app one never
// did, and the docs described the manual script's behaviour for both. This walks the
// artifact list against both so the next addition cannot land in only one.
func TestTeardownPathsDoNotDrift(t *testing.T) {
	manualPath := filepath.Join("..", "..", "..", "scripts", "fleet-unenroll.sh")
	manualBytes, err := os.ReadFile(manualPath)
	if err != nil {
		t.Fatalf("read %s: %v", manualPath, err)
	}
	manual := string(manualBytes)
	svc := &Service{cfg: &config.Config{WGInterface: "wgfleet"}}
	inApp := svc.hostTeardownScript("fleet", svc.hostOverlayRetireScript(&models.Host{}))

	// Each artifact is named by a token that must appear in BOTH implementations.
	// They are written differently ($IF vs "$WG_IF"), so match on the stable part.
	for _, artifact := range []struct{ what, token string }{
		{"the sudoers grant", "/etc/sudoers.d/fleet"},
		{"the trusted CA", "/etc/ssh/fleet_ca.pub"},
		{"the revocation list", "/etc/ssh/fleet_krl"},
		{"the principal files", "/etc/ssh/auth_principals"},
		{"the sshd drop-in", "/etc/ssh/sshd_config.d/00-fleet.conf"},
		{"the appended sshd block", "# Fleet Terminal"},
		{"the sshd validity check", "sshd -t"},
		{"the login-only account", "-login"},
		{"the WireGuard interface", "wg-quick down"},
		{"the WireGuard boot unit", "wg-quick@"},
		{"the WireGuard config", ".fleet-disabled"},
	} {
		if !strings.Contains(inApp, artifact.token) {
			t.Errorf("in-app teardown does not handle %s (%q)", artifact.what, artifact.token)
		}
		if !strings.Contains(manual, artifact.token) {
			t.Errorf("scripts/fleet-unenroll.sh does not handle %s (%q)", artifact.what, artifact.token)
		}
	}
}

// stubOverlay is a minimal Overlay whose only interesting behaviour is the host-side
// retire script the teardown embeds.
type stubOverlay struct{ retire string }

func (stubOverlay) Name() string { return "openvpn" }
func (stubOverlay) EnsureServer(context.Context, overlay.RunFunc) (string, error) {
	return "", nil
}
func (stubOverlay) ProvisionHost(context.Context, uuid.UUID, string, string, overlay.RunFunc, overlay.RunFunc) (string, error) {
	return "", nil
}
func (stubOverlay) PrepareHost(context.Context, uuid.UUID, string, string, overlay.RunFunc) (overlay.HostBringup, error) {
	return overlay.HostBringup{}, nil
}
func (stubOverlay) RetireJump(context.Context, uuid.UUID, overlay.RunFunc) (string, error) {
	return "", nil
}
func (s stubOverlay) RetireHostScript() overlay.HostBringup {
	return overlay.HostBringup{Script: s.retire, Marker: "RETIRED_OPENVPN"}
}
