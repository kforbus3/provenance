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
