package sshgw

import "testing"

func TestLoginTier(t *testing.T) {
	// Sudo tier: privileged account, default principals (nil -> issuer default).
	user, principals := LoginTier(true, "fleet", "alice")
	if user != "fleet" {
		t.Fatalf("sudo login user = %q, want %q", user, "fleet")
	}
	if principals != nil {
		t.Fatalf("sudo principals = %v, want nil (issuer default)", principals)
	}

	// Login-only tier: distinct account + the "fleet-login" principal that maps
	// to it; the username is informational only and namespaced ("user:alice") so it
	// can't collide with a fleet principal. It must NOT carry the "fleet"
	// principal, or it could open the sudo account.
	user, principals = LoginTier(false, "fleet", "alice")
	if user != "fleet-login" {
		t.Fatalf("login-only user = %q, want %q", user, "fleet-login")
	}
	want := []string{"fleet-login", "user:alice"}
	if len(principals) != len(want) {
		t.Fatalf("login-only principals = %v, want %v", principals, want)
	}
	for i := range want {
		if principals[i] != want[i] {
			t.Fatalf("login-only principals = %v, want %v", principals, want)
		}
	}
	for _, p := range principals {
		if p == "fleet" {
			t.Fatalf("login-only cert must not carry the privileged 'fleet' principal: %v", principals)
		}
	}

	// A non-default SSH user keeps the "-login" suffix convention.
	if u, _ := LoginTier(false, "ops", "bob"); u != "ops-login" {
		t.Fatalf("login-only user for ops = %q, want %q", u, "ops-login")
	}
}
