package enrollment

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/config"
)

func testScript(t *testing.T) string {
	t.Helper()
	s := &Service{cfg: &config.Config{WGSubnet: "10.9.0.0/24", WGJumpIP: "10.9.0.1", WGPort: 51820}}
	return s.bootstrapScript(
		"fleet", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI-ca fleet-ca",
		"10.9.0.5", "jumppubkey=", "vpn.example.com:51820", "",
		uuid.MustParse("abcdef01-2345-6789-abcd-ef0123456789"),
	)
}

// The operator runs the bootstrap script with `sudo sh`, not bash — it declares
// #!/bin/sh and the enrollment docs and dialog both invoke it that way. A
// bashism that slipped into any phase would only surface on a dash/ash host at
// enrollment time, so check the whole generated script parses as POSIX sh.
func TestBootstrapScriptIsPOSIXSh(t *testing.T) {
	script := testScript(t)
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
		t.Errorf("generated script is not valid POSIX sh: %v\n%s\n---\n%s", err, out, script)
	}
}

// accountBlock extracts the account-creation loop from the generated script so it
// can be executed against stub tools, instead of asserting on its text.
func accountBlock(t *testing.T) string {
	t.Helper()
	script := testScript(t)
	start := strings.Index(script, "FLEETSHELL=")
	if start < 0 {
		t.Fatal("account-creation block not found in the generated script")
	}
	end := strings.Index(script[start:], "\ndone\n")
	if end < 0 {
		t.Fatal("account-creation loop is not terminated")
	}
	return "set -e\nLOGIN=fleet\nNOSUDO=fleet-login\n" + script[start:start+end+len("\ndone\n")]
}

// runWithStubs executes a shell fragment with a PATH holding only the stubs given
// as name -> exit code, so account creation can be made to fail deterministically.
func runWithStubs(t *testing.T, fragment string, exits map[string]int) error {
	t.Helper()
	dir := t.TempDir()
	for name, code := range exits {
		stub := fmt.Sprintf("#!/bin/sh\nexit %d\n", code)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(stub), 0o755); err != nil {
			t.Fatalf("write stub %s: %v", name, err)
		}
	}
	cmd := exec.Command("/bin/sh", "-c", fragment)
	cmd.Env = append(os.Environ(), "PATH="+dir)
	out, err := cmd.CombinedOutput()
	t.Logf("stub run output: %s", out)
	return err
}

// A host that trusts the Fleet CA but has no account to map principals onto
// accepts nobody. Account creation used to end in `|| true` with both tools'
// stderr sent to /dev/null, so the phase printed its CA_OK marker and enrollment
// reported success while the accounts silently did not exist. Both tools failing
// must fail the phase.
func TestBootstrapScriptFailsWhenAccountCreationFails(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skipf("no /bin/sh: %v", err)
	}
	block := accountBlock(t)

	// id says the account doesn't exist; both creation tools fail.
	err := runWithStubs(t, block, map[string]int{"id": 1, "useradd": 1, "adduser": 1})
	if err == nil {
		t.Error("account creation failing on both tools must fail the phase, not be swallowed")
	}

	// Sanity: when the account ends up present, the block succeeds.
	if err := runWithStubs(t, block, map[string]int{"id": 0, "useradd": 0, "adduser": 0}); err != nil {
		t.Errorf("block should succeed when the accounts exist, got %v", err)
	}

	// busybox hosts have no useradd; falling back to adduser must still succeed.
	// `id` fails first (no account), then succeeds after adduser runs — a stub
	// can't be stateful, so approximate with adduser succeeding and id passing.
	if err := runWithStubs(t, block, map[string]int{"id": 0, "useradd": 127, "adduser": 0}); err != nil {
		t.Errorf("adduser fallback should succeed, got %v", err)
	}
}

// The script is useless unless it refuses to run unprivileged (it edits sshd
// config and brings up WireGuard) and tells the operator the TTY-carrying form
// that lets sudo prompt — piping into `ssh host sudo sh` fails on any host
// without NOPASSWD.
func TestBootstrapScriptRootGuardNamesTheTTYForm(t *testing.T) {
	script := testScript(t)
	if !strings.Contains(script, `if [ "$(id -u)" != 0 ]`) {
		t.Error("script must refuse to run as a non-root user")
	}
	if !strings.Contains(script, "ssh -t USER@HOST") {
		t.Errorf("root guard should point at the `ssh -t` form, got:\n%s", script)
	}
}
