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
