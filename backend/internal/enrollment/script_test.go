package enrollment

import (
	"os/exec"
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
