package identity

import (
	"testing"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/config"
	princ "github.com/fleet-terminal/backend/internal/principals"
)

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// scopeForHost adds the host-scoped principal while retaining the fleet-wide one
// ("fleet" authenticates the jump-host hop). Crucially it must never leak another
// host's principal — that distinctness is what stops a cert authenticating on a
// host it was not minted for once that host is locked down.
func TestScopeForHostAddsScopedKeepsGlobal(t *testing.T) {
	id, other := uuid.New(), uuid.New()
	i := &Issuer{cfg: &config.Config{}}

	got := i.scopeForHost([]string{princ.Global, "alice"}, id)
	if !has(got, princ.Global) {
		t.Errorf("must keep the fleet-wide principal for the jump hop: %v", got)
	}
	if !has(got, princ.Host(id)) {
		t.Errorf("must add the host-scoped principal: %v", got)
	}
	if has(got, princ.Host(other)) {
		t.Errorf("cert leaked a different host's principal: %v", got)
	}
	if !has(got, "alice") {
		t.Errorf("informational principal dropped: %v", got)
	}

	gotLogin := i.scopeForHost([]string{princ.GlobalLogin, "alice"}, id)
	if !has(gotLogin, princ.GlobalLogin) || !has(gotLogin, princ.HostLogin(id)) {
		t.Errorf("login tier wrong: %v", gotLogin)
	}
}

// The system login-only principal set backs the ad-hoc command runner's no-sudo
// tier. Like the interactive tier it must not carry the fleet-wide "fleet": a host
// that is not yet locked down still maps "fleet" to the PRIVILEGED account, so a
// set carrying it would open root for a user whose Host.Sudo was withheld — with
// only the backend's choice of account name standing in the way.
func TestSystemHostLoginPrincipalsNeverCarryThePrivilegedPrincipal(t *testing.T) {
	id := uuid.New()

	for _, tc := range []struct {
		name     string
		lockdown bool
	}{{"default", false}, {"host-scoped-only", true}} {
		t.Run(tc.name, func(t *testing.T) {
			i := &Issuer{cfg: &config.Config{HostScopedOnly: tc.lockdown}}
			got := i.SystemHostLoginPrincipals(id)
			if has(got, princ.Global) {
				t.Errorf("login-only set carries %q, which maps to the sudo account: %v", princ.Global, got)
			}
			if has(got, princ.Host(id)) {
				t.Errorf("login-only set carries the privileged host-scoped principal: %v", got)
			}
			if !has(got, princ.GlobalLogin) {
				t.Errorf("login-only set must map to the no-sudo account: %v", got)
			}
			if tc.lockdown && !has(got, princ.HostLogin(id)) {
				t.Errorf("under lockdown the host-scoped login principal is required: %v", got)
			}
		})
	}

	// The privileged set is unchanged and still carries "fleet" for the jump hop —
	// it is what the login tier pairs with as its jump-hop credential.
	priv := (&Issuer{cfg: &config.Config{}}).SystemHostPrincipals(id)
	if !has(priv, princ.Global) {
		t.Errorf("privileged system set must keep %q for the jump hop: %v", princ.Global, priv)
	}
}
