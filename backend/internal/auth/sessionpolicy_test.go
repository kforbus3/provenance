package auth

import "testing"

func TestIPAllowed(t *testing.T) {
	cases := []struct {
		name  string
		ip    string
		list  []string
		allow bool
	}{
		{"cidr match", "10.20.30.50", []string{"10.20.30.0/24"}, true},
		{"cidr miss", "10.20.31.50", []string{"10.20.30.0/24"}, false},
		{"bare ip exact", "192.168.1.7", []string{"192.168.1.7"}, true},
		{"bare ip miss", "192.168.1.8", []string{"192.168.1.7"}, false},
		{"multiple, second matches", "172.16.5.5", []string{"10.0.0.0/8", "172.16.0.0/12"}, true},
		{"whitespace tolerated", "10.1.1.1", []string{" 10.0.0.0/8 "}, true},
		{"empty entries skipped", "10.1.1.1", []string{"", "10.0.0.0/8"}, true},
		{"ipv6 cidr", "2001:db8::1", []string{"2001:db8::/32"}, true},
		{"unparseable ip never allowed", "not-an-ip", []string{"0.0.0.0/0"}, false},
		{"garbage cidr ignored", "10.1.1.1", []string{"nonsense", "10.0.0.0/8"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ipAllowed(c.ip, c.list); got != c.allow {
				t.Errorf("ipAllowed(%q, %v) = %v, want %v", c.ip, c.list, got, c.allow)
			}
		})
	}
}
