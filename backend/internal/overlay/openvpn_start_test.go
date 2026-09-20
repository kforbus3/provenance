package overlay

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/config"
)

func startTestOverlay() *OpenVPN {
	return &OpenVPN{
		cfg: &config.Config{
			WGSubnet: "10.100.0.0/24", WGJumpIP: "10.100.0.1",
			OVPNSubnet: "10.101.0.0/24", OVPNJumpIP: "10.101.0.1", OVPNPort: 1194,
		},
		pki: stubCA{},
	}
}

// stubCA stands in for the overlay PKI, which needs a database. Only CRLPEM is
// exercised by the tests in this package; the issuing methods are here to satisfy
// the interface and fail loudly if a test starts depending on them.
type stubCA struct{ crlErr error }

func (stubCA) EnsureCA(context.Context) error { return nil }
func (stubCA) CACertPEM() []byte              { return []byte(testCAPEM) }
func (stubCA) IssueServer(string, []string, []net.IP, time.Duration) ([]byte, []byte, error) {
	return nil, nil, errors.New("stubCA cannot issue")
}
func (stubCA) IssueClient(string, time.Duration) ([]byte, []byte, string, error) {
	return nil, nil, "", errors.New("stubCA cannot issue")
}
func (stubCA) RecordClient(context.Context, uuid.UUID, string, string, time.Time) error { return nil }
func (c stubCA) CRLPEM(context.Context) ([]byte, error) {
	if c.crlErr != nil {
		return nil, c.crlErr
	}
	return []byte(testCRLPEM), nil
}

const testCAPEM = "-----BEGIN CERTIFICATE-----\ntest-ca\n-----END CERTIFICATE-----\n"

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
// starting: the liveness guard was `pgrep -f 'openvpn .*server.conf'`, and Provenance runs
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
	script := o.JumpServerScript([]byte("ca"), []byte("crt"), []byte("key"), []byte(testCRLPEM), conf)

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
	script := o.HostInstallScript([]byte("ca"), []byte("crt"), []byte("key"), o.ClientConfig("vpn.example.com:1194"), "10.101.0.27")

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
	// Both exit NON-zero for a unit that is merely inactive — the shape that used to
	// abort the diagnostics block under `set -e` and print nothing at all.
	write("journalctl", "exit 1")
	write("systemctl", "exit 3")
	write("tail", "exit 0")
	return dir
}

// The host script used to print OVPN_HOST_CONFIGURED unconditionally after a fixed
// sleep, and report the address Provenance MEANT to assign. So a host that never brought a
// tunnel up was indistinguishable from one that did — and on a switch from WireGuard,
// that false success is what authorized tearing the working tunnel down.
func TestHostScriptReportsTheObservedTunnelAddress(t *testing.T) {
	o := startTestOverlay()
	script := o.HostInstallScript([]byte("ca"), []byte("crt"), []byte("key"), o.ClientConfig("vpn.example.com:1194"), "10.101.0.27")
	// Everything from the wait loop to the end of the generated script: the loop, the
	// success branch and the whole diagnostics branch, already balanced.
	i := strings.Index(script, "OVPN_IP=")
	if i < 0 {
		t.Fatal("generated script no longer contains the tunnel-wait loop")
	}
	wait := script[i:]

	run := func(ipOutput string) string {
		// `set -e` is on for the real script, so the harness runs the block the same
		// way: a diagnostics command that exits non-zero must not swallow the report.
		cmd := exec.Command("sh", "-ec", wait)
		cmd.Env = append(os.Environ(), "PATH="+stubBin(t, ipOutput)+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("wait loop failed: %v\n%s", err, out)
		}
		return string(out)
	}

	// No tun device: the tunnel is not up, and the script must say so — and must
	// still say the rest, including the endpoint the client was told to dial. The
	// diagnostics used to run under `set -e` with commands that exit non-zero for an
	// inactive unit, so the block died before printing anything and a failed
	// enrollment showed an empty log with no cause.
	got := run("")
	if !strings.Contains(got, "OVPN_HOST_NO_TUNNEL") || strings.Contains(got, "OVPN_HOST_CONFIGURED") {
		t.Errorf("host with no tunnel reported %q — enrollment would treat this as success", strings.TrimSpace(got))
	}
	// The endpoint line is empty here (no client.ovpn on disk in a unit test), but it
	// must be REACHED — everything after it is the diagnosis.
	if !strings.Contains(got, "OVPN_REMOTE=") {
		t.Errorf("failure report does not report the endpoint the client dialled:\n%s", got)
	}
	if !strings.Contains(got, "openvpn client log") {
		t.Errorf("failure report was cut short before the log section:\n%s", got)
	}
	if !strings.Contains(got, "unit state follows") {
		t.Errorf("failure report does not fall back to unit state when the log is empty:\n%s", got)
	}

	// Tunnel up at the address the server was told to pin: success.
	got = run("tun0             UNKNOWN        10.101.0.27/24")
	if !strings.Contains(got, "OVPN_HOST_IP=10.101.0.27") || !strings.Contains(got, "OVPN_HOST_CONFIGURED") {
		t.Errorf("host with a live tunnel reported %q", strings.TrimSpace(got))
	}

	// A tunnel at some OTHER address is not success: it means the ccd pin did not
	// apply and the server handed out a pool address, so Provenance would be dialing an
	// address nothing answers on. The script reports what it saw and lets
	// checkHostBringup call it — but it must not report the pinned address it wanted.
	got = run("tun0             UNKNOWN        10.101.0.99/24")
	if !strings.Contains(got, "OVPN_HOST_IP=10.101.0.99") {
		t.Errorf("host on a pool address did not report the address it actually got:\n%s", got)
	}
	if strings.Contains(got, "OVPN_HOST_IP=10.101.0.27") {
		t.Error("script reported the address it wanted rather than the one on the device")
	}
}

// A bring-up is only a success if the host came up at the address Provenance assigned it.
// "The script exited 0" is not that, and neither is "some tunnel exists".
func TestCheckHostBringup(t *testing.T) {
	for _, tc := range []struct {
		name, out, wantErr string
	}{
		{"no address at all", "OVPN_HOST_CONFIGURED\n", "no OpenVPN tunnel"},
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

// A tunnel that is up now and enabled by nothing is not an enrolled host.
//
// alma1 was enrolled, reachable for days, rebooted, and came back with no
// overlay. The config had been written to /etc/openvpn/prov-overlay.conf --
// the path only the legacy openvpn@.service reads -- because the script tried
// that location first and /etc/openvpn exists on RHEL as the parent of client/
// and server/. RHEL 9 ships only openvpn-client@.service, which reads
// /etc/openvpn/client/%i.conf. Both enables failed, the bare-daemon fallback
// brought the tunnel up, and enrollment reported success.
func TestHostScriptWritesTheConfigWhereBothUnitTemplatesLook(t *testing.T) {
	o := startTestOverlay()
	got := o.HostInstallScript([]byte("ca"), []byte("crt"), []byte("key"),
		o.ClientConfig("vpn.example.com:1194"), "10.101.0.2")

	for _, path := range []string{
		"/etc/openvpn/client/prov-overlay.conf", // openvpn-client@ (current)
		"/etc/openvpn/prov-overlay.conf",        // openvpn@ (legacy)
	} {
		if !strings.Contains(got, "cp "+provDir+"/client.ovpn "+path) {
			t.Errorf("config is never written to %s, so the unit that reads it cannot start", path)
		}
	}
	// Unconditionally, not "A else B": the else branch never ran on the
	// distribution that needed it.
	if strings.Contains(got, "/etc/openvpn/prov-overlay.conf 2>/dev/null || cp") {
		t.Error("still writes one location only if the other failed")
	}
	// The template that current distributions actually ship must be tried first.
	if strings.Index(got, "enable --now openvpn-client@") > strings.Index(got, "enable --now openvpn@prov-overlay") {
		t.Error("tries the legacy openvpn@ template before openvpn-client@")
	}
}

func TestNonPersistentTunnelIsReportedRatherThanPassedOff(t *testing.T) {
	detail, err := checkHostBringup(
		"OVPN_HOST_IP=10.101.0.2\nOVPN_HOST_NOT_PERSISTENT\nOVPN_HOST_CONFIGURED\n", "10.101.0.2")
	if err != nil {
		t.Fatalf("a working tunnel must still enroll: %v", err)
	}
	if !strings.Contains(detail, "next reboot") {
		t.Errorf("detail %q does not warn that the tunnel will not survive a reboot", detail)
	}
}

func TestPersistentTunnelCarriesNoWarning(t *testing.T) {
	detail, err := checkHostBringup(
		"OVPN_HOST_IP=10.101.0.2\nOVPN_HOST_PERSISTENT\nOVPN_HOST_CONFIGURED\n", "10.101.0.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(detail, "next reboot") {
		t.Errorf("warned about a tunnel that is enabled at boot: %q", detail)
	}
}

// A FIPS-enabled Ubuntu 22.04 cannot bring up an OpenVPN tunnel at all: its OpenVPN
// 2.5 does not read ciphers from the OpenSSL 3 FIPS provider, so every --data-ciphers
// value is refused and --show-ciphers lists nothing. No configuration fixes it.
//
// The enrollment error was twenty lines of OpenVPN log ending "NCP cipher list
// contains unsupported ciphers or is too long", which does not lead anyone to "your
// distribution's OpenVPN cannot see the FIPS module". When the host can name the
// cause, the error leads with it.
func TestAHostsOwnDiagnosisLeadsTheError(t *testing.T) {
	out := "OVPN_WAITED=60s\nOVPN_HOST_NO_TUNNEL\nOVPN_NO_CIPHERS\n" +
		"OVPN_DIAGNOSIS=this host runs FIPS mode and its OpenVPN (2.5.11) reports no usable data ciphers\n" +
		"--- openvpn client log ---\nUnsupported cipher in --data-ciphers: AES-256-GCM\n"
	_, err := checkHostBringup(out, "10.100.0.5")
	if err == nil {
		t.Fatal("a bring-up with no tunnel must be an error")
	}
	if !strings.Contains(err.Error(), "FIPS mode") || !strings.Contains(err.Error(), "no usable data ciphers") {
		t.Errorf("the host's diagnosis is not in the error: %v", err)
	}
	if strings.Contains(err.Error(), "NCP cipher list") {
		t.Errorf("the raw log is still leading the error: %v", err)
	}
}

// Without a diagnosis, the generic hint and log tail are still what an operator gets.
func TestWithoutADiagnosisTheOldErrorIsKept(t *testing.T) {
	_, err := checkHostBringup("OVPN_HOST_NO_TUNNEL\nOVPN_REMOTE=vpn.example.com:1194\n", "10.100.0.5")
	if err == nil || !strings.Contains(err.Error(), "vpn.example.com:1194") {
		t.Errorf("the remote-address hint was lost: %v", err)
	}
}

// A config rewritten under a running server must restart it.
//
// This is the failure that made the OpenVPN overlay flap for two days: moving the
// overlay off the WireGuard subnet rewrote the tunnel network in server.conf, the
// daemon went on enforcing the old one, and the script reported
// OVPN_SERVER_ALREADY_RUNNING every time:
//
//	MULTI ERROR: primary virtual IP for prov-h-8295... (10.101.0.2) violates tunnel
//	network/netmask constraint (10.100.0.0/255.255.255.0)
//
// The harness runs the REAL gate from the generated script, with the process checks
// and the launch stubbed by shell functions so a test can stand in for a daemon. What
// it asserts is behaviour, not text: an unchanged config must still take the
// already-running path (no blip on ordinary re-enrollment), and a changed one must
// restart and record the new fingerprint.
func TestServerRestartsOntoAChangedConfig(t *testing.T) {
	cases := []struct {
		name          string
		running       bool
		activeContent string // "" means no .active file at all
		wantMarkers   []string
		wantAbsent    []string
		wantActive    bool // .active must end up matching server.conf
	}{
		{
			name: "unchanged config is left alone", running: true, activeContent: "same",
			wantMarkers: []string{"OVPN_SERVER_ALREADY_RUNNING"},
			wantAbsent:  []string{"OVPN_SERVER_CONFIG_CHANGED", "OVPN_SERVER_STARTED"},
		},
		{
			name: "changed config restarts the server", running: true, activeContent: "an older config\n",
			wantMarkers: []string{"OVPN_SERVER_CONFIG_CHANGED", "OVPN_SERVER_STARTED"},
			wantAbsent:  []string{"OVPN_SERVER_ALREADY_RUNNING"},
			wantActive:  true,
		},
		{
			name: "no fingerprint and nothing running starts it", running: false, activeContent: "",
			wantMarkers: []string{"OVPN_SERVER_STARTED"},
			wantAbsent:  []string{"OVPN_SERVER_ALREADY_RUNNING"},
			wantActive:  true,
		},
		{
			name: "no fingerprint under a running daemon restarts it", running: true, activeContent: "",
			wantMarkers: []string{"OVPN_SERVER_CONFIG_CHANGED", "OVPN_SERVER_STARTED"},
			wantAbsent:  []string{"OVPN_SERVER_ALREADY_RUNNING"},
			wantActive:  true,
		},
	}

	o := startTestOverlay()
	conf, err := o.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	script := o.JumpServerScript([]byte("ca"), []byte("crt"), []byte("key"), []byte(testCRLPEM), conf)
	// To the end of the script: the gate is the last thing it renders, and cutting at
	// the first "fi" stops short of the launch (which is how this test first passed
	// while exercising nothing).
	gate := script[strings.Index(script, "_ovpn_conf_changed=1"):]
	if !strings.Contains(gate, "openvpn --config") {
		t.Fatalf("the extracted gate does not contain the launch, so this test proves nothing:\n%s", gate)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			confPath := filepath.Join(dir, "server.conf")
			activePath := filepath.Join(dir, "server.conf.active")
			if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.activeContent != "" {
				body := tc.activeContent
				if body == "same" {
					body = conf
				}
				if err := os.WriteFile(activePath, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.running {
				if err := os.WriteFile(filepath.Join(dir, "running"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			// Stand-ins for the daemon and the process table. `kill` stops the
			// stub server; `openvpn` starts it; both record that they ran, so a
			// gate that skips the restart cannot pass by accident.
			stubs := "ST=" + dir + "\n" +
				"ovpn_server_running() { [ -f \"$ST/running\" ]; }\n" +
				"ovpn_server_pids() { [ -f \"$ST/running\" ] && echo 4242; }\n" +
				"kill() { rm -f \"$ST/running\"; echo \"KILLED $*\" >> \"$ST/acts\"; }\n" +
				"sleep() { :; }\n" +
				"openvpn() { touch \"$ST/running\"; echo \"LAUNCHED $*\" >> \"$ST/acts\"; }\n"
			harness := stubs + strings.ReplaceAll(gate, provDir, dir) + "\n"

			out, err := exec.Command("sh", "-c", harness).CombinedOutput()
			if err != nil {
				t.Fatalf("gate failed: %v\n%s", err, out)
			}
			got := string(out)
			for _, want := range tc.wantMarkers {
				if !strings.Contains(got, want) {
					t.Errorf("gate did not report %s\noutput: %s", want, got)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("gate reported %s when it must not\noutput: %s", absent, got)
				}
			}
			acts, _ := os.ReadFile(filepath.Join(dir, "acts"))
			if tc.wantActive {
				if !strings.Contains(string(acts), "LAUNCHED") {
					t.Errorf("no launch happened, so the daemon is still on the old config; acts=%q", acts)
				}
				active, err := os.ReadFile(activePath)
				if err != nil {
					t.Fatalf("no fingerprint recorded after a start: %v", err)
				}
				if string(active) != conf {
					t.Errorf("fingerprint does not match the config the daemon was started with:\n%s", active)
				}
			} else {
				if strings.Contains(string(acts), "LAUNCHED") || strings.Contains(string(acts), "KILLED") {
					t.Errorf("an unchanged config disturbed a running server: acts=%q", acts)
				}
			}
			if tc.running && tc.activeContent == "same" {
				if _, err := os.Stat(filepath.Join(dir, "running")); err != nil {
					t.Errorf("the running server was stopped for an unchanged config: %v", err)
				}
			}
		})
	}
}

// The jump host's OpenVPN must be 2.6+ or a FIPS client cannot use the tunnel.
//
// A 2.6 FIPS client against a 2.5 server completes the TLS handshake, takes its
// PUSH_REPLY, and then fails to derive data-channel keys, because pre-2.6 key
// expansion is the TLS 1.0 PRF and FIPS forbids it:
//
//	TLS Error: PRF calculation failed ... the policy does not allow it
//	TLS Error: generate_key_expansion failed
//
// The device comes up with the right address and carries nothing. The error appears on
// the CLIENT while the cause is the server, so the server script has to check itself.
func TestJumpServerRequiresOpenVPN26(t *testing.T) {
	o := startTestOverlay()
	conf, err := o.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	script := o.JumpServerScript([]byte("ca"), []byte("crt"), []byte("key"), []byte(testCRLPEM), conf)
	// The version block, up to where the material starts being written.
	i := strings.Index(script, "_ovpn_major_minor()")
	j := strings.Index(script, "mkdir -p ")
	if i < 0 || j < 0 || j < i {
		t.Fatal("the version check is no longer where this test reads it")
	}
	block := script[i:j]

	for _, tc := range []struct {
		version    string
		upgradesTo string // what a successful apt upgrade would install; "" = none available
		wantPre26  bool
		wantForce  bool
		wantStuck  bool
	}{
		{version: "2.6.12", wantPre26: false},
		{version: "2.5.11", upgradesTo: "2.6.12", wantPre26: true, wantForce: true},
		{version: "2.5.11", upgradesTo: "", wantPre26: true, wantStuck: true},
		{version: "3.0.0", wantPre26: false},
	} {
		t.Run(tc.version+"->"+tc.upgradesTo, func(t *testing.T) {
			dir := t.TempDir()
			bin := t.TempDir()
			// `openvpn --version` reports whatever the state file holds, so an
			// "upgrade" is the stub apt-get rewriting it.
			if err := os.WriteFile(filepath.Join(dir, "version"), []byte(tc.version), 0o644); err != nil {
				t.Fatal(err)
			}
			write := func(name, body string) {
				if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			write("openvpn", `echo "OpenVPN $(cat `+dir+`/version) x86_64-pc-linux-gnu"`)
			upgrade := ":"
			if tc.upgradesTo != "" {
				upgrade = `case "$*" in *backports*) echo ` + tc.upgradesTo + ` > ` + dir + `/version ;; esac`
			}
			write("apt-get", upgrade)

			// Exported: the script reads the codename in a subshell (it sources
			// /etc/os-release there), so an unexported variable is invisible to it —
			// which is also why a host whose os-release omits VERSION_CODENAME
			// reports STILL_PRE26 instead of quietly skipping the check.
			harness := "PATH=" + bin + ":$PATH\nexport PATH\n" +
				"VERSION_CODENAME=jammy\nexport VERSION_CODENAME\n" + block
			out, err := exec.Command("sh", "-c", harness).CombinedOutput()
			if err != nil {
				t.Fatalf("version block failed: %v\n%s", err, out)
			}
			got := string(out)
			if tc.wantPre26 != strings.Contains(got, "OVPN_SERVER_PRE26=") {
				t.Errorf("OVPN_SERVER_PRE26 presence wrong for %s: %s", tc.version, got)
			}
			if tc.wantForce && !strings.Contains(got, "OVPN_SERVER_UPGRADED=2.6") {
				t.Errorf("a 2.5 server was not upgraded, so a FIPS host's tunnel will carry "+
					"nothing: %s", got)
			}
			if tc.wantStuck && !strings.Contains(got, "OVPN_SERVER_STILL_PRE26=") {
				t.Errorf("an un-upgradable 2.5 server is not reported, so the enrollment gives "+
					"no hint why the tunnel is dead: %s", got)
			}
			if !strings.Contains(got, "OVPN_SERVER_VERSION=") {
				t.Errorf("the server's version is not reported at all: %s", got)
			}
		})
	}
}

// An upgraded binary is still the old code until the process restarts, so the upgrade
// must force one even when the config is byte-identical.
func TestUpgradedServerBinaryForcesARestart(t *testing.T) {
	o := startTestOverlay()
	conf, err := o.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	script := o.JumpServerScript([]byte("ca"), []byte("crt"), []byte("key"), []byte(testCRLPEM), conf)
	gate := script[strings.Index(script, "_ovpn_conf_changed=1"):]

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	// Identical fingerprint: only the forced restart can make this start anything.
	if err := os.WriteFile(filepath.Join(dir, "server.conf.active"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "running"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stubs := "ST=" + dir + "\n_ovpn_force_restart=1\n" +
		"ovpn_server_running() { [ -f \"$ST/running\" ]; }\n" +
		"ovpn_server_pids() { [ -f \"$ST/running\" ] && echo 4242; }\n" +
		"kill() { rm -f \"$ST/running\"; }\n" +
		"sleep() { :; }\n" +
		"openvpn() { touch \"$ST/running\"; echo LAUNCHED >> \"$ST/acts\"; }\n"
	out, err := exec.Command("sh", "-c", stubs+strings.ReplaceAll(gate, provDir, dir)).CombinedOutput()
	if err != nil {
		t.Fatalf("gate failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "OVPN_SERVER_CONFIG_CHANGED") {
		t.Errorf("an upgraded binary did not restart the server, so it keeps running the old "+
			"code and a FIPS client still cannot make keys: %s", out)
	}
	acts, _ := os.ReadFile(filepath.Join(dir, "acts"))
	if !strings.Contains(string(acts), "LAUNCHED") {
		t.Error("nothing was started after the upgrade")
	}
}
