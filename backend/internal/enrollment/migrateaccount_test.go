package enrollment

import (
	"context"
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
			&models.Host{Hostname: "h", SSHUser: "fleet"}, bad)
		if err == nil || !strings.Contains(err.Error(), "invalid account name") {
			t.Errorf("account name %q was accepted (err=%v)", bad, err)
		}
	}
}

// Migrating a host that logs in as root would hand userdel the host's root
// account. Refuse before any connection is made.
func TestMigrateRefusesToDeleteRoot(t *testing.T) {
	svc := &Service{}
	_, err := svc.MigrateLoginAccount(context.Background(),
		&models.Host{Hostname: "h", SSHUser: "root"}, "prov")
	if err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("migrating a root-login host was allowed (err=%v)", err)
	}
}

// A host already on the target account is a no-op, not an error and not a round
// trip: the post-rename sweep runs over every host, including ones already moved.
func TestMigrateIsANoOpWhenAlreadyOnTheTargetAccount(t *testing.T) {
	svc := &Service{}
	res, err := svc.MigrateLoginAccount(context.Background(),
		&models.Host{Hostname: "h", SSHUser: "prov"}, "prov")
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
