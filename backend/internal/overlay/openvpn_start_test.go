package overlay

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fleet-terminal/backend/internal/config"
)

func startTestOverlay() *OpenVPN {
	return &OpenVPN{cfg: &config.Config{
		WGSubnet: "10.100.0.0/24", WGJumpIP: "10.100.0.1", OVPNPort: 1194,
	}}
}

// section returns the text of script between start and the first end after it,
// failing the test if the shape it depends on is gone. Tests below execute pieces of
// the REAL generated script rather than a re-typed copy, so a rewrite that drops the
// piece is a test failure rather than a silently vacuous test.
func section(t *testing.T, script, start, end string) string {
	t.Helper()
	i := strings.Index(script, start)
	if i < 0 {
		t.Fatalf("generated script no longer contains %q", start)
	}
	rest := script[i:]
	j := strings.Index(rest, end)
	if j < 0 {
		t.Fatalf("section starting %q is not terminated by %q", start, end)
	}
	return rest[:j+len(end)]
}

// lineWith returns the first line of script containing want.
func lineWith(t *testing.T, script, want string) string {
	t.Helper()
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, want) {
			return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), "\\"))
		}
	}
	t.Fatalf("generated script has no line containing %q", want)
	return ""
}

// This is the bug that let an OpenVPN overlay report itself healthy without ever
// starting: the liveness guard was `pgrep -f 'openvpn .*server.conf'`, and Fleet runs
// these scripts as `sh -c "<the whole script>"`, so the script's own shell has that
// exact command line in its argv. pgrep -f matches command lines, so the guard always
// answered "already running", the launch never happened, and every enrollment onto the
// overlay reported success while the server did not exist.
//
// NOTE: these two tests are meaningful only on Linux. macOS pgrep -f does not match
// the `sh -c` argv the same way, so the pre-fix guard passes locally and fails in CI
// (and failed in production). Verified by reverting the guard and running under
// golang:1.26 in Docker.
//
// The harness below is the load-bearing part: it runs the REAL guard from a shell
// whose argv carries the REAL launch command, with no openvpn running anywhere. That
// is the exact arrangement that failed in production, and the Docker validation
// harness could not see it because it runs the script from a file, where argv is just
// the filename.
func TestServerGuardDoesNotMatchItsOwnShell(t *testing.T) {
	if _, err := exec.LookPath("pgrep"); err != nil {
		t.Skipf("no pgrep available: %v", err)
	}
	o := startTestOverlay()
	conf, err := o.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	script := o.JumpServerScript([]byte("ca"), []byte("crt"), []byte("key"), conf)

	guard := section(t, script, "ovpn_server_running() {", "\n}\n")
	launch := lineWith(t, script, "openvpn --config")
	if strings.Contains(launch, "'") {
		t.Fatalf("launch line has a quote this harness cannot carry verbatim: %q", launch)
	}

	// `: 'text'` is a no-op whose argument puts the launch command in this shell's
	// argv — exactly as the real script's own text does.
	harness := guard + "\n: '" + launch + "'\n" +
		"if ovpn_server_running; then echo RUNNING; else echo NOT_RUNNING; fi\n"

	out, err := exec.Command("sh", "-c", harness).CombinedOutput()
	if err != nil {
		t.Fatalf("guard harness failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "NOT_RUNNING" {
		t.Errorf("guard reports %q with no openvpn running — it is matching its own shell, "+
			"so the server is never started and enrollment reports a healthy overlay that does not exist", got)
	}
}

// The managed host's client guard carries the same hazard and the same fix.
func TestClientGuardDoesNotMatchItsOwnShell(t *testing.T) {
	if _, err := exec.LookPath("pgrep"); err != nil {
		t.Skipf("no pgrep available: %v", err)
	}
	o := startTestOverlay()
	script := o.HostInstallScript([]byte("ca"), []byte("crt"), []byte("key"), o.ClientConfig("vpn.example.com:1194"))

	guard := section(t, script, "ovpn_client_running() {", "\n}\n")
	launch := lineWith(t, script, "openvpn --config")
	harness := guard + "\n: '" + launch + "'\n" +
		"if ovpn_client_running; then echo RUNNING; else echo NOT_RUNNING; fi\n"

	out, err := exec.Command("sh", "-c", harness).CombinedOutput()
	if err != nil {
		t.Fatalf("guard harness failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "NOT_RUNNING" {
		t.Errorf("client guard reports %q with no openvpn running: %s", got, out)
	}
}

// stubBin puts fake executables on PATH so the tunnel-wait loop can be run in a test:
// `ip` reports whatever the caller wants, `sleep` returns instantly.
func stubBin(t *testing.T, ipOutput string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("ip", "cat <<'EOF'\n"+ipOutput+"\nEOF")
	write("sleep", "exit 0")
	write("journalctl", "exit 0")
	write("tail", "exit 0")
	return dir
}

// The host script used to print OVPN_HOST_CONFIGURED unconditionally after a fixed
// sleep, and report the address Fleet MEANT to assign. So a host that never brought a
// tunnel up was indistinguishable from one that did — and on a switch from WireGuard,
// that false success is what authorized tearing the working tunnel down.
func TestHostScriptReportsTheObservedTunnelAddress(t *testing.T) {
	o := startTestOverlay()
	script := o.HostInstallScript([]byte("ca"), []byte("crt"), []byte("key"), o.ClientConfig("vpn.example.com:1194"))
	wait := section(t, script, "OVPN_IP=", "OVPN_HOST_NO_TUNNEL")
	wait += "\nfi\n" // close the if the section cuts through

	run := func(ipOutput string) string {
		cmd := exec.Command("sh", "-c", wait)
		cmd.Env = append(os.Environ(), "PATH="+stubBin(t, ipOutput)+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("wait loop failed: %v\n%s", err, out)
		}
		return string(out)
	}

	// No tun device: the tunnel is not up, and the script must say so.
	if got := run(""); !strings.Contains(got, "OVPN_HOST_NO_TUNNEL") || strings.Contains(got, "OVPN_HOST_CONFIGURED") {
		t.Errorf("host with no tunnel reported %q — enrollment would treat this as success", strings.TrimSpace(got))
	}

	// Tunnel up: report the address actually on the device.
	got := run("tun0             UNKNOWN        10.100.0.27/24")
	if !strings.Contains(got, "OVPN_HOST_IP=10.100.0.27") || !strings.Contains(got, "OVPN_HOST_CONFIGURED") {
		t.Errorf("host with a live tunnel reported %q", strings.TrimSpace(got))
	}
}

// A bring-up is only a success if the host came up at the address Fleet assigned it.
// "The script exited 0" is not that, and neither is "some tunnel exists".
func TestCheckHostBringup(t *testing.T) {
	for _, tc := range []struct {
		name, out, wantErr string
	}{
		{"no address at all", "OVPN_HOST_CONFIGURED\n", "no tunnel address"},
		{"tunnel up on a pool address", "OVPN_HOST_IP=10.100.0.99\nOVPN_HOST_CONFIGURED\n", "ccd pin"},
		{"assigned address", "OVPN_HOST_IP=10.100.0.27\nOVPN_HOST_CONFIGURED\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			detail, err := checkHostBringup(tc.out, "10.100.0.27")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !strings.Contains(detail, "10.100.0.27") {
					t.Errorf("detail %q does not report the observed address", detail)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted an unproven tunnel, detail=%q", detail)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not explain the failure (want %q)", err, tc.wantErr)
			}
		})
	}
}
