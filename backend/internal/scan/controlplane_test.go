package scan

import (
	"testing"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/models"
)

func TestIsControlPlaneHost(t *testing.T) {
	cfg := &config.Config{
		JumpHost:          "jumphost:22",
		WGJumpIP:          "10.100.0.1",
		WGJumpEndpoint:    "gw.example.com:51820",
		ControlPlaneHosts: []string{"fleet-host", "10.0.0.5"},
	}

	cases := []struct {
		name string
		host *models.Host
		want bool
	}{
		{"nil host", nil, false},
		{"plain managed host", &models.Host{Hostname: "web-01", Address: "10.0.9.9"}, false},
		{"control-plane tag", &models.Host{Hostname: "web-01", Tags: []string{"prod", "Control-Plane"}}, true},
		{"protected tag", &models.Host{Hostname: "web-01", Tags: []string{"protected"}}, true},
		{"declared by hostname", &models.Host{Hostname: "fleet-host"}, true},
		{"declared by address", &models.Host{Hostname: "box", Address: "10.0.0.5"}, true},
		{"jump host by name", &models.Host{Hostname: "jumphost"}, true},
		{"jump host by wg ip", &models.Host{Hostname: "box", WGAddress: "10.100.0.1"}, true},
		{"jump host by wg endpoint host", &models.Host{Address: "gw.example.com"}, true},
		{"case-insensitive declared", &models.Host{Hostname: "FLEET-HOST"}, true},
	}
	for _, tc := range cases {
		if got := isControlPlaneHost(tc.host, cfg); got != tc.want {
			t.Errorf("%s: isControlPlaneHost = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestHostPart(t *testing.T) {
	cases := map[string]string{
		"jumphost:22":          "jumphost",
		"gw.example.com:51820": "gw.example.com",
		"10.100.0.1":           "10.100.0.1",
		"bare-host":            "bare-host",
		"":                     "",
	}
	for in, want := range cases {
		if got := hostPart(in); got != want {
			t.Errorf("hostPart(%q) = %q, want %q", in, got, want)
		}
	}
}
