package principals

import (
	"testing"

	"github.com/google/uuid"
)

func TestHostScopedNamesAreStableAndDistinct(t *testing.T) {
	a := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	b := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	if Host(a) != "fleet-h-"+a.String() {
		t.Fatalf("Host(a) = %q", Host(a))
	}
	if HostLogin(a) != "fleet-login-h-"+a.String() {
		t.Fatalf("HostLogin(a) = %q", HostLogin(a))
	}
	// A principal minted for host A must never equal one for host B — that
	// distinctness is the entire point of host scoping.
	if Host(a) == Host(b) || HostLogin(a) == HostLogin(b) {
		t.Fatal("host-scoped principals collide across hosts")
	}
	// Host-scoped principals must not equal the fleet-wide ones.
	if Host(a) == Global || HostLogin(a) == GlobalLogin {
		t.Fatal("host-scoped principal collides with a fleet-wide principal")
	}
}

// The namespaced username principal must never be able to equal a fleet or
// host-scoped principal, even if the username is chosen adversarially.
func TestUserPrincipalCannotCollide(t *testing.T) {
	h := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	adversarial := []string{"fleet", GlobalLogin, Host(h), HostLogin(h), "fleet-h-" + h.String()}
	for _, name := range adversarial {
		if User(name) == Global || User(name) == GlobalLogin || User(name) == Host(h) || User(name) == HostLogin(h) {
			t.Fatalf("User(%q) = %q collides with a fleet/host principal", name, User(name))
		}
	}
}
