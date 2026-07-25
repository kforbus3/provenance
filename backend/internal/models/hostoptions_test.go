package models

import "testing"

func TestRouterOSAPIPort(t *testing.T) {
	cases := []struct {
		name string
		opts HostOptions
		want int
	}{
		{"generic host", HostOptions{}, 0},
		{"deviceType routeros default port", HostOptions{DeviceType: "routeros"}, 8728},
		{"deviceType routeros explicit port", HostOptions{DeviceType: "routeros", APIPort: 8729}, 8729},
		{"legacy routerOsApi flag still honored", HostOptions{RouterOSAPI: true}, 8728},
		{"legacy flag + explicit port", HostOptions{RouterOSAPI: true, APIPort: 8729}, 8729},
		{"apiPort set but generic -> 0", HostOptions{APIPort: 8728}, 0},
	}
	for _, c := range cases {
		h := Host{Options: c.opts}
		if got := h.RouterOSAPIPort(); got != c.want {
			t.Errorf("%s: RouterOSAPIPort() = %d, want %d", c.name, got, c.want)
		}
	}
}
