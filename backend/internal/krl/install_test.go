package krl

import (
	"os/exec"
	"strings"
	"testing"
)

// The bug these cover: the KRL was pushed to every host, verified on disk, and enforced
// nowhere. `sshd -T` reported "revokedkeys none" fleet-wide while /etc/ssh/prov_krl was
// refreshed hourly with the full serial list. The directive is appended to the sshd
// drop-in that the trust installer rewrites with `cat >`, so any re-install dropped it and
// nothing added it back.

// Order is the safety property: a RevokedKeys directive naming a file that does not exist
// makes sshd -t fail, and on a host whose config does not validate the next reload refuses
// every connection. So the list must be on disk before the directive is added.
func TestInstallScriptWritesTheKRLBeforeEnablingIt(t *testing.T) {
	s := InstallScript("QUJD")
	write := strings.Index(s, "> /etc/ssh/prov_krl")
	enable := strings.Index(s, "echo 'RevokedKeys /etc/ssh/prov_krl'")
	if write < 0 || enable < 0 {
		t.Fatalf("script does not both write the KRL and enable it:\n%s", s)
	}
	if write > enable {
		t.Error("the directive is added before the KRL exists; sshd -t would fail and the " +
			"host is one reload from refusing every connection")
	}
}

// Adding the directive must be validated before it is activated, and rolled back if sshd
// rejects it. Never lock a host out to enforce revocation.
func TestInstallScriptRollsBackIfSSHDRejectsTheConfig(t *testing.T) {
	s := InstallScript("QUJD")
	validate := strings.Index(s, "sshd -t")
	rollback := strings.Index(s, `sed -i '\#^RevokedKeys /etc/ssh/prov_krl#d'`)
	reload := strings.Index(s, "systemctl reload sshd")
	if validate < 0 || rollback < 0 || reload < 0 {
		t.Fatalf("script is missing validate/rollback/reload:\n%s", s)
	}
	if !(validate < rollback && rollback < reload) {
		t.Errorf("expected validate -> rollback -> reload, got %d/%d/%d", validate, rollback, reload)
	}
}

// The assertion must ask sshd what it will ENFORCE, not whether a file exists. A config
// that enforces nothing is perfectly valid, which is exactly how this went unnoticed: the
// push verified the file had landed and called that success.
func TestInstallScriptAssertsEnforcementNotFilePresence(t *testing.T) {
	s := InstallScript("QUJD")
	if !strings.Contains(s, "sshd -T") {
		t.Error("script never consults sshd's effective config, so it cannot know the KRL " +
			"is enforced — only that a file was written")
	}
	for _, tok := range []string{Enforced, PresentUnverified, NotEnforced, RolledBack} {
		if !strings.Contains(s, tok) {
			t.Errorf("script cannot report %q, so a caller cannot distinguish the outcomes", tok)
		}
	}
	// "written but unconfirmed" must not be reported as enforced.
	if Enforced == PresentUnverified {
		t.Error("the two outcomes must be distinguishable")
	}
}

// A host that lost the directive must regain it from an ordinary push, with no
// re-enrolment — that is what makes distribution self-healing across a fleet that has
// already drifted.
func TestInstallScriptAddsTheDirectiveWhenAbsent(t *testing.T) {
	s := InstallScript("QUJD")
	if !strings.Contains(s, `grep -q '^RevokedKeys'`) {
		t.Error("script does not check whether the directive is missing, so it cannot heal a host that lost it")
	}
	if !strings.Contains(s, "00-prov.conf") || !strings.Contains(s, "/etc/ssh/sshd_config") {
		t.Error("script must handle both the drop-in and a host with no Include")
	}
}

// The script is fed to `sh`, so it has to be valid shell. A syntax error would fail on
// every host at once, and the output would look like a fleet-wide connectivity problem.
func TestInstallScriptIsValidShell(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh available")
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(InstallScript("QUJD"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script is not valid shell: %v\n%s", err, out)
	}
}

// InstallCommand quotes the script for a single-command SSH invocation. The script
// contains single quotes (the sed expressions), so a quoting mistake would truncate it
// mid-script — which can leave the directive added and unvalidated.
func TestInstallCommandQuotingIsLossless(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh available")
	}
	want := InstallScript("QUJD")
	quoted := strings.TrimPrefix(InstallCommand("QUJD"), "sudo sh -c ")
	if quoted == InstallCommand("QUJD") {
		t.Fatal("InstallCommand does not run the script through a root shell")
	}
	// Let the shell itself unquote it, and compare with the original.
	cmd := exec.Command("sh", "-c", "printf '%s' "+quoted)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("quoted command is not parseable by sh: %v", err)
	}
	if string(out) != want {
		t.Errorf("quoting is not lossless.\n got: %q\nwant: %q", string(out), want)
	}
}

// A drop-in file that exists is not a drop-in file sshd reads. Enrolment writes
// 00-prov.conf unconditionally, so on a host whose sshd_config has no Include the
// drop-in sits there inert — and choosing the target by file existence alone put the
// directive somewhere sshd never opens, while every check downstream looked healthy.
func TestInstallScriptPicksTheFileSSHDActuallyReads(t *testing.T) {
	s := InstallScript("QUJD")
	if !strings.Contains(s, "Include") {
		t.Error("target selection does not check for an Include of sshd_config.d, so it " +
			"can write the directive into a drop-in sshd never reads")
	}
	// The existence test alone must not be what decides it.
	idx := strings.Index(s, `[ -f "$DROP" ]`)
	if idx < 0 {
		t.Fatal("expected the drop-in existence check to still be part of the condition")
	}
	line := s[idx:]
	if nl := strings.IndexByte(line, '\n'); nl > 0 {
		line = line[:nl]
	}
	if !strings.Contains(line, "Include") {
		t.Errorf("the drop-in is chosen on existence alone: %q", line)
	}
}

// "sshd disagrees" and "sshd could not be asked" are different answers, and collapsing
// them reported a host that plainly said `revokedkeys none` as merely unconfirmed — the
// softer of the two, when the evidence was conclusive.
func TestInstallScriptSeparatesDisagreementFromUnreadable(t *testing.T) {
	s := InstallScript("QUJD")
	if !strings.Contains(s, "if SSHD_T=$(sshd -T 2>/dev/null); then") {
		t.Fatal("the script does not capture sshd -T separately, so it cannot tell a " +
			"failed invocation from a negative answer")
	}
	// The unverified branch must be reachable ONLY when sshd -T could not run, i.e.
	// after the closing of the successful-invocation branch.
	ran := strings.Index(s, "if SSHD_T=$(sshd -T")
	notEnforced := strings.Index(s, "echo "+NotEnforced)
	unverified := strings.Index(s, "echo "+PresentUnverified)
	if notEnforced < 0 || unverified < 0 {
		t.Fatal("both outcomes must be reachable")
	}
	if !(ran < notEnforced && notEnforced < unverified) {
		t.Errorf("expected the conclusive not-enforced answer inside the sshd -T branch, "+
			"before the unreadable fallback: ran=%d notEnforced=%d unverified=%d",
			ran, notEnforced, unverified)
	}
}

// When the drop-in turns out not to be read, the script must correct itself rather than
// report a guess — the fallback is what makes a host like that self-heal.
func TestInstallScriptFallsBackToTheMainConfig(t *testing.T) {
	s := InstallScript("QUJD")
	if !strings.Contains(s, `if [ "$TARGET" != /etc/ssh/sshd_config ]; then`) {
		t.Error("no fallback: a host whose drop-in is not read stays unenforced forever")
	}
	// The fallback must validate and roll back like the first attempt does.
	fb := strings.Index(s, `if [ "$TARGET" != /etc/ssh/sshd_config ]; then`)
	if fb < 0 {
		t.FailNow()
	}
	tail := s[fb:]
	if !strings.Contains(tail, "sshd -t") || !strings.Contains(tail, "sed -i") {
		t.Error("the fallback appends to the main config without validating or rolling back")
	}
}
