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

func TestScopeForHostAdditiveKeepsGlobal(t *testing.T) {
	id := uuid.New()
	i := &Issuer{cfg: &config.Config{HostScopedOnly: false}}

	got := i.scopeForHost([]string{princ.Global, "alice"}, id)
	if !has(got, princ.Global) {
		t.Errorf("additive mode should keep the fleet-wide principal: %v", got)
	}
	if !has(got, princ.Host(id)) {
		t.Errorf("additive mode should add the host-scoped principal: %v", got)
	}
	if !has(got, "alice") {
		t.Errorf("informational principal dropped: %v", got)
	}

	gotLogin := i.scopeForHost([]string{princ.GlobalLogin, "alice"}, id)
	if !has(gotLogin, princ.GlobalLogin) || !has(gotLogin, princ.HostLogin(id)) {
		t.Errorf("additive login tier wrong: %v", gotLogin)
	}
}

func TestScopeForHostLockdownDropsGlobal(t *testing.T) {
	id, other := uuid.New(), uuid.New()
	i := &Issuer{cfg: &config.Config{HostScopedOnly: true}}

	got := i.scopeForHost([]string{princ.Global, "alice"}, id)
	if has(got, princ.Global) {
		t.Errorf("lockdown must drop the fleet-wide principal: %v", got)
	}
	if !has(got, princ.Host(id)) {
		t.Errorf("lockdown must keep the host-scoped principal: %v", got)
	}
	// The cert must NOT carry another host's principal — that is what stops it
	// authenticating anywhere but its target host.
	if has(got, princ.Host(other)) {
		t.Errorf("cert leaked a different host's principal: %v", got)
	}
	if !has(got, "alice") {
		t.Errorf("informational principal dropped: %v", got)
	}
}
