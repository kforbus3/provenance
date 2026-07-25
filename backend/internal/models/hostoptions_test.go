package models

import "testing"

func TestRouterOSAPIPort(t *testing.T) {
	cases := []struct {
		name string
		opts HostOptions
		want int
	}{
		{"not a routeros host", HostOptions{}, 0},
		{"routeros default port", HostOptions{RouterOSAPI: true}, 8728},
		{"routeros explicit port", HostOptions{RouterOSAPI: true, APIPort: 8729}, 8729},
		{"apiPort set but not routeros -> 0", HostOptions{APIPort: 8728}, 0},
	}
	for _, c := range cases {
		h := Host{Options: c.opts}
		if got := h.RouterOSAPIPort(); got != c.want {
			t.Errorf("%s: RouterOSAPIPort() = %d, want %d", c.name, got, c.want)
		}
	}
}
