package hostexec

import (
	"strings"
	"testing"
)

// "This container's compose project is recorded at /home/keith/test2, but that
// directory is not there — it was probably deployed from somewhere else."
//
// It was there, with exactly the compose file being looked for. /home/keith is
// mode 700 and the script ran as an ordinary account, so `cd` failed.
//
// The mistake underneath: a "privileged" run in this product means the connection
// lands in the host's PRIVILEGED ACCOUNT rather than its login-only one — sshd
// decides which account opens. It does not mean the commands run as root. Every
// script written for these features assumed the second.
func TestPrivilegedReExecsUnderSudoWhenAvailable(t *testing.T) {
	got := Privileged("echo hello\n")

	if !strings.Contains(got, "sudo -n true") {
		t.Error("does not test for non-interactive sudo before using it")
	}
	if !strings.Contains(got, "exec sudo -n /bin/sh -s") {
		t.Error("does not re-exec the script as root")
	}
	// -n, or a host that would PROMPT hangs on a password nobody is there to type.
	if strings.Contains(got, "exec sudo /bin/sh") {
		t.Error("sudo without -n can prompt")
	}
	// Already root: nothing to do, and `sudo` may not even exist.
	if !strings.Contains(got, `[ "$(id -u)" -ne 0 ]`) {
		t.Error("does not skip the wrapper when already root")
	}
}

func TestTheScriptStillRunsWithoutSudo(t *testing.T) {
	// A host where the account has no sudo must behave exactly as before rather
	// than failing outright — the wrapper is an improvement, not a requirement.
	got := Privileged("echo hello\n")
	// `exec` replaces the shell, so the copy after `fi` runs only when the branch
	// was not taken. Both copies must be present for that to work.
	if strings.Count(got, "echo hello") != 2 {
		t.Errorf("expected the body once inside the sudo branch and once after it:\n%s", got)
	}
	if !strings.Contains(got, "\nfi\n") {
		t.Error("the sudo branch is not closed, so the fallback is unreachable")
	}
}

func TestTheBodyIsPassedVerbatim(t *testing.T) {
	// A compose file is full of $. Expanding it on the way to the root shell
	// would write something different from what was reviewed.
	body := "cat <<'EOF'\nimage: ${TAG:-latest}\nEOF\n"
	got := Privileged(body)
	if !strings.Contains(got, "<<'PROVENANCE_PRIV_EOF'") {
		t.Error("the heredoc is not quoted, so the body is expanded on the way through")
	}
	if !strings.Contains(got, "${TAG:-latest}") {
		t.Error("the body did not survive intact")
	}
}
