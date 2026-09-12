// Package hostexec holds the small rules about HOW a script runs on a host, as
// opposed to what it does. Neutral so that both the stack deploy and the update
// rollout can use them without either importing the other.
package hostexec

import "strings"

// Privileged re-runs a script as root where the account can, and unchanged where
// it cannot.
//
// A "privileged" run in this product means the connection lands in the host's
// PRIVILEGED ACCOUNT rather than its login-only one — sshd decides which account
// opens, which is the point. It does not mean the commands run as root. Every
// script here was therefore running as an ordinary user, and the parts that need
// more failed in ways that read as something else entirely:
//
//	"this container's compose project is recorded at /home/keith/test2, but that
//	 directory is not there — it was probably deployed from somewhere else"
//
// The directory was there, with exactly the compose file being looked for.
// /home/keith is mode 700, so the account could not traverse it, and a failed
// `cd` is indistinguishable from a missing directory unless you ask separately.
// The same applies to writing a compose file into /opt/stacks, which belongs to
// a deploy account, and to reading `docker ps` on a host where this account is
// not in the docker group.
//
// So: re-exec under non-interactive sudo when it is available. `exec` replaces
// the shell, so the copy below it runs only when sudo is NOT available — a host
// where the account has no sudo behaves exactly as before rather than failing
// outright. `-n` so a host that would PROMPT fails immediately instead of hanging
// on a password nobody is there to type.
func Privileged(script string) string {
	var b strings.Builder
	b.WriteString(`if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then` + "\n")
	// A quoted heredoc: the body is handed to the root shell verbatim, so nothing
	// in a compose file is expanded twice on the way through.
	b.WriteString("exec sudo -n /bin/sh -s <<'PROVENANCE_PRIV_EOF'\n")
	b.WriteString(script)
	b.WriteString("\nPROVENANCE_PRIV_EOF\n")
	b.WriteString("fi\n")
	b.WriteString(script)
	b.WriteString("\n")
	return b.String()
}
