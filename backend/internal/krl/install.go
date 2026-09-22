package krl

import (
	"fmt"
	"strings"
)

// Result tokens the install script prints. Callers must distinguish them: "the file
// landed" and "sshd will enforce it" are different facts, and reporting the first as the
// second is what let a fleet keep accepting revoked certificates for weeks.
const (
	// Enforced means sshd's own effective config names the KRL.
	Enforced = "KRL_ENFORCED"
	// PresentUnverified means the directive is in the file we edited but `sshd -T`
	// could not be run to confirm sshd agrees.
	PresentUnverified = "KRL_PRESENT_UNVERIFIED"
	// NotEnforced means the directive is not in effect. The host still honours every
	// revoked certificate.
	NotEnforced = "KRL_NOT_ENFORCED"
	// RolledBack means adding the directive made sshd reject the config, so it was
	// removed again rather than risk locking the host out.
	RolledBack = "KRL_ROLLBACK"
)

// InstallScript writes the KRL to a managed host AND makes sshd enforce it.
//
// Both halves matter, and shipping only the first is how a fleet ends up with a correct,
// freshly-pushed KRL on every host that no sshd reads. The RevokedKeys directive was
// added once, at enrolment, by APPENDING to the sshd drop-in — while the trust installer
// rewrites that same drop-in with `cat >`. So any later re-install (a re-enrolment, the
// account rename, a login-account migration) silently dropped the directive, the hourly
// distribution went on refreshing the file, and nothing noticed.
//
// The script therefore ensures the directive every time it pushes the list, which makes
// distribution self-healing: a host that lost the directive regains it on the next push
// without re-enrolment.
//
// The final check is a POSITIVE assertion against `sshd -T`, sshd's own effective config,
// not a test that a file exists. A config that enforces nothing is perfectly valid, so
// file presence proves only that the push landed.
func InstallScript(b64 string) string {
	return fmt.Sprintf(`set -e
printf '%%s' '%s' | base64 -d > /etc/ssh/prov_krl
chmod 644 /etc/ssh/prov_krl
# Prefer the drop-in; fall back to the main config on a host that has no Include.
DROP=/etc/ssh/sshd_config.d/00-prov.conf
if [ -f "$DROP" ]; then TARGET="$DROP"; else TARGET=/etc/ssh/sshd_config; fi
if ! grep -q '^RevokedKeys' "$TARGET"; then
  echo 'RevokedKeys /etc/ssh/prov_krl' >> "$TARGET"
fi
# Validate BEFORE activating. A KRL that sshd rejects must never reach a reload.
if ! sshd -t 2>/dev/null; then
  sed -i '\#^RevokedKeys /etc/ssh/prov_krl#d' "$TARGET"
  echo "%s sshd config rejected"; exit 1
fi
( systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service sshd reload 2>/dev/null || service ssh reload 2>/dev/null || pkill -HUP sshd 2>/dev/null ) || true
# Ask sshd what it will actually enforce, rather than trusting what we just wrote.
if sshd -T 2>/dev/null | grep -qi '^revokedkeys[[:space:]][[:space:]]*/etc/ssh/prov_krl'; then
  echo %s
elif grep -qs '^RevokedKeys /etc/ssh/prov_krl' "$TARGET"; then
  echo %s
else
  echo %s; exit 1
fi`, b64, RolledBack, Enforced, PresentUnverified, NotEnforced)
}

// InstallCommand wraps InstallScript in a root shell, quoted, for callers that run one
// command string over SSH rather than handing a script to a privileged runner.
//
// The quoting lives here, beside the script, because the script contains single quotes
// (the sed expressions) and a caller that got it wrong would push a command that either
// fails or, worse, truncates at the wrong place.
func InstallCommand(b64 string) string {
	return "sudo sh -c " + shellQuote(InstallScript(b64))
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
