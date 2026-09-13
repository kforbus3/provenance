package enrollment

import (
	"context"
	"strings"
	"testing"

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
