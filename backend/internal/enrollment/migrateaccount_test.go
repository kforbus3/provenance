package enrollment

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/config"
	"github.com/kforbus3/provenance/backend/internal/models"
)

// The account name is interpolated into a root shell script on a managed host, so
// what may pass is a security boundary rather than a tidiness rule.
func TestMigrateRejectsAccountNamesThatAreNotAccountNames(t *testing.T) {
	svc := &Service{}
	for _, bad := range []string{
		"prov; rm -rf /",
		"prov rm",
		"$(id)",
		"`id`",
		"prov'\nrm -rf /\n'",
		"-rf",
		"Prov",
		"0day",
		strings.Repeat("a", 32),
	} {
		_, err := svc.MigrateLoginAccount(context.Background(),
			&models.Host{Hostname: "h", SSHUser: "fleet"}, MigrateOptions{User: bad})
		if err == nil || !strings.Contains(err.Error(), "invalid account name") {
			t.Errorf("account name %q was accepted (err=%v)", bad, err)
		}
	}
}

// The migration's last step deletes the old account. That is fine for an account
// enrollment created, and not fine for one the operator nominated — which is what
// a host enrolled against an existing login has. "root" is the obvious case;
// coreswitch, which logs in as "admin", is the one that actually occurred.
func TestMigrateRefusesToDeleteAnAccountProvenanceDidNotCreate(t *testing.T) {
	svc := &Service{}
	for _, account := range []string{"root", "admin", "ubuntu", "ec2-user", "keith"} {
		_, err := svc.MigrateLoginAccount(context.Background(),
			&models.Host{Hostname: "h", SSHUser: account}, MigrateOptions{User: "prov"})
		if err == nil || !strings.Contains(err.Error(), "did not create") {
			t.Errorf("migrating a host that logs in as %q was allowed (err=%v)", account, err)
		}
	}
	// The accounts enrollment does create must still be migratable, or the feature
	// refuses itself. Checked on the predicate rather than through
	// MigrateLoginAccount, which would get past the guard and go on to need a CA.
	for _, account := range []string{"prov", "fleet"} {
		if !provenanceManagedAccount(account) {
			t.Errorf("%q is created by enrollment but is not treated as migratable", account)
		}
	}
	for _, account := range []string{"root", "admin", "ubuntu", "", "Prov"} {
		if provenanceManagedAccount(account) {
			t.Errorf("%q is not an account enrollment creates, but is treated as migratable", account)
		}
	}
}

// A host already on the target account is a no-op, not an error and not a round
// trip: the post-rename sweep runs over every host, including ones already moved.
func TestMigrateIsANoOpWhenAlreadyOnTheTargetAccount(t *testing.T) {
	svc := &Service{}
	res, err := svc.MigrateLoginAccount(context.Background(),
		&models.Host{Hostname: "h", SSHUser: "prov"}, MigrateOptions{User: "prov"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Migrated {
		t.Error("reported a migration that did not happen")
	}
	if len(res.Steps) == 0 || !strings.Contains(res.Steps[0], "nothing to do") {
		t.Errorf("steps = %v, want it to say there was nothing to do", res.Steps)
	}
}

// The retire script runs on a host whose sshd is currently trusting the CA file it
// is about to delete. `sshd -t` fails on a TrustedUserCAKeys pointing at a missing
// file, and a host whose sshd config does not validate is one reload away from
// refusing every connection — including the one that would fix it.
func TestRetireRemovesTheSSHDConfigBeforeTheCAItReferences(t *testing.T) {
	s := retireAccountScript("fleet")

	dropIn := strings.Index(s, "rm -f /etc/ssh/sshd_config.d/00-fleet.conf")
	caFile := strings.Index(s, "rm -f /etc/ssh/fleet_ca.pub")
	if dropIn < 0 || caFile < 0 {
		t.Fatalf("retire script does not remove both artefacts:\n%s", s)
	}
	if dropIn > caFile {
		t.Error("removes the CA file before the sshd config that references it")
	}

	validate := strings.Index(s, "sshd -t")
	reload := strings.Index(s, "systemctl reload sshd")
	if validate < 0 || reload < 0 || validate > reload {
		t.Error("reloads sshd without validating the config first")
	}
	if validate > caFile {
		t.Error("validates sshd before the config edit rather than after it")
	}
}

// Both accounts go, and the login-only one goes first: it is the one with no sudo,
// so a failure part-way leaves the privileged account — the one the operator can
// still get in through — rather than the other way round.
func TestRetireRemovesBothAccountsLoginOnlyFirst(t *testing.T) {
	s := retireAccountScript("fleet")
	if !strings.Contains(s, `for U in "$NOSUDO" "$OLD"`) {
		t.Errorf("retire script does not remove both accounts login-only-first:\n%s", s)
	}
}

// The old account name is what gets interpolated, so it must actually appear.
func TestRetireTargetsTheAccountItWasGiven(t *testing.T) {
	s := retireAccountScript("legacyuser")
	if !strings.Contains(s, "OLD='legacyuser'") {
		t.Fatalf("retire script does not target the account it was given:\n%s", s)
	}
}

// The KRL directive is appended on its own, and on a host with no
// /etc/ssh/sshd_config.d the old installer put it in the MAIN sshd_config —
// nowhere near the marker block the teardown strips. Deleting fleet_krl while a
// RevokedKeys line still names it passes `sshd -t` at migration time and fails on
// the host's NEXT reload or reboot, which is the worst shape a failure can have:
// the host locks itself out long after anything connects it to this change.
func TestRetireStripsTheKRLDirectiveBeforeDeletingTheKRL(t *testing.T) {
	s := retireAccountScript("fleet")

	strip := strings.Index(s, "RevokedKeys /etc/ssh/fleet_krl#d")
	if strip < 0 {
		t.Fatalf("retire script never removes the RevokedKeys directive:\n%s", s)
	}
	// Anchor on the command, not the phrase: the surrounding comments mention
	// "sshd -t" too, and matching those would compare the wrong positions.
	validate := strings.Index(s, "if ! sshd -t")
	remove := strings.Index(s, "rm -f /etc/ssh/fleet_ca.pub /etc/ssh/fleet_krl")
	if validate < 0 || remove < 0 {
		t.Fatalf("retire script is missing the validate/remove steps:\n%s", s)
	}
	if strip > validate {
		t.Error("strips the RevokedKeys directive after validating, so the check passes on a config that is about to dangle")
	}
	if strip > remove {
		t.Error("deletes the KRL before removing the directive that names it")
	}
	// The main config is where the old installer put it when the host had no
	// drop-in directory; checking only the drop-ins would miss exactly those hosts.
	if !strings.Contains(s, "/etc/ssh/sshd_config 2>/dev/null") {
		t.Error("only strips the directive from drop-ins, not the main sshd_config")
	}
}

// The same dangling reference in the teardown path: it removes both KRLs, so both
// spellings of the directive have to go with them.
func TestTeardownStripsBothKRLDirectives(t *testing.T) {
	svc := &Service{cfg: &config.Config{WGInterface: "wgprov"}}
	s := svc.hostTeardownScript("fleet", "")
	if !strings.Contains(s, `RevokedKeys /etc/ssh/\(prov\|fleet\)_krl`) {
		t.Errorf("teardown removes the KRL files but leaves the directive naming them:\n%s", s)
	}
}

// Removal must be opt-in. The bulk sweep that caused the incident deleted the old
// account on every host it touched, including the one Provenance itself runs on,
// because removal was unconditional. Creating an account is reversible; deleting
// one is not, so the default has to be the reversible half.
func TestRemovalIsOptIn(t *testing.T) {
	var zero MigrateOptions
	if zero.RemoveOld {
		t.Fatal("MigrateOptions defaults to removing the old account")
	}
	if zero.ConfirmControlPlane {
		t.Fatal("MigrateOptions defaults to overriding the control-plane guard")
	}
}

// The row must be written BEFORE the old account is removed: the row is what makes
// the new account reachable, so a failed write after removal leaves a host
// reachable by nothing. Pinned on the source order, which is the thing that was
// wrong -- the assertion cannot be made against a nil gateway.
func TestTheRowIsRecordedBeforeTheOldAccountIsRemoved(t *testing.T) {
	src, err := os.ReadFile("migrateaccount.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	record := strings.Index(body, "ChangeHostSSHUser(ctx, host.ID, newUser)")
	retire := strings.Index(body, "retireAccountScript(oldUser)))")
	if record < 0 || retire < 0 {
		t.Fatalf("cannot find both steps (record=%d retire=%d)", record, retire)
	}
	if record > retire {
		t.Error("removes the old account before recording the new one, so a failed write strands the host")
	}
}

// A host with no /etc/ssh/sshd_config.d Include has its directives appended to the
// MAIN sshd_config under a marker, and the migration appends a SECOND block for the
// new CA. Stripping "the marker block" matched both and removed the new trust with
// the old, leaving a host that trusts no CA — offline, unreachable, and with a
// config that `sshd -t` is perfectly happy with, because trusting nothing is valid.
//
// This is what took the Proxmox host down. The retire step must edit by CA path and
// must assert the current trust survives, not merely that the config parses.
func TestRetireKeepsTheCurrentCATrustOnAHostWithNoDropInInclude(t *testing.T) {
	s := retireAccountScript("fleet")

	// It must target the OLD CA path specifically...
	if !strings.Contains(s, "TrustedUserCAKeys /etc/ssh/fleet_ca.pub#d") {
		t.Error("does not remove the old CA directive by path")
	}
	// ...and never blanket-strip directives under any marker, which is what took
	// the new trust with it.
	if strings.Contains(s, `skip && /^(PubkeyAuthentication|TrustedUserCAKeys|AuthorizedPrincipalsFile) /`) {
		t.Error("still strips every directive under a marker block, which removes the CURRENT CA trust too")
	}
	// The positive assertion: sshd -t cannot tell "trusts nothing" from "correct".
	if !strings.Contains(s, "TrustedUserCAKeys /etc/ssh/prov_ca.pub") {
		t.Error("never checks that trust for the current CA survived")
	}
	assertIdx := strings.Index(s, "is missing after cleanup")
	validate := strings.Index(s, "if ! sshd -t")
	if assertIdx < 0 || validate < 0 || assertIdx > validate {
		t.Error("checks CA trust after validating/reloading rather than before")
	}
}

// Retiring the superseded account is deliberately a SECOND pass, run once the fleet is
// verified healthy on the new account. But by then every host is already on the target,
// and the "already on the target" early return used to fire before RemoveOld was ever
// looked at — so the retirement pass became unreachable across the whole fleet at exactly
// the moment it was meant to run, stranding the old accounts with no supported way off.
//
// "Nothing to migrate" is not "nothing to do".
func TestRetireStillRunsWhenAlreadyOnTheTargetAccount(t *testing.T) {
	svc := &Service{}
	// current="fleet" has no superseded account, so this reaches the retire path and
	// stops there without needing a host to dial — which is the point: it must get PAST
	// the early return.
	res, err := svc.MigrateLoginAccount(context.Background(),
		&models.Host{Hostname: "h", SSHUser: "fleet"},
		MigrateOptions{User: "fleet", RemoveOld: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	joined := strings.Join(res.Steps, "; ")
	if strings.Contains(joined, "nothing to do") {
		t.Errorf("took the no-op path with RemoveOld set: %v\n"+
			"the retirement pass is unreachable again", res.Steps)
	}
	if !strings.Contains(joined, "nothing to retire") {
		t.Errorf("steps = %v, want it to have reached the retire path", res.Steps)
	}
}

// Without RemoveOld the no-op must stay a no-op: the adopt-only sweep runs over every
// host including ones already moved, and must not become a round trip.
func TestAlreadyOnTargetStaysANoOpWithoutRemoveOld(t *testing.T) {
	svc := &Service{}
	res, err := svc.MigrateLoginAccount(context.Background(),
		&models.Host{Hostname: "h", SSHUser: "prov"}, MigrateOptions{User: "prov"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Steps) == 0 || !strings.Contains(res.Steps[0], "nothing to do") {
		t.Errorf("steps = %v, want the no-op", res.Steps)
	}
}

// The retire path is the DESTRUCTIVE half, so it must carry the same control-plane guard
// as a migration. A guard that only covers the gentler caller is not a guard — and this
// is the exact shape of the sweep that deleted the operators' own account on the
// Provenance host.
func TestRetireOnAControlPlaneHostIsRefusedWithoutConfirmation(t *testing.T) {
	svc := &Service{cfg: &config.Config{}}
	host := &models.Host{Hostname: "sshman", SSHUser: "prov", Tags: []string{"control-plane"}}

	_, err := svc.MigrateLoginAccount(context.Background(), host,
		MigrateOptions{User: "prov", RemoveOld: true})
	if err == nil {
		t.Fatal("retiring on a control-plane host was allowed without confirmation")
	}
	if !strings.Contains(err.Error(), "control plane") {
		t.Errorf("error = %v, want it to name the control plane", err)
	}
}

// supersededAccount is a pair, not a history: the rename had exactly two names, and
// inventing a chain would mean deleting accounts nobody asked about.
func TestSupersededAccountIsOnlyTheRenamePair(t *testing.T) {
	if got := supersededAccount("prov"); got != "fleet" {
		t.Errorf("supersededAccount(prov) = %q, want fleet", got)
	}
	for _, in := range []string{"fleet", "root", "admin", "svc-prov", ""} {
		if got := supersededAccount(in); got != "" {
			t.Errorf("supersededAccount(%q) = %q, want empty", in, got)
		}
	}
}
