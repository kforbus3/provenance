package enrollment

import (
	"strings"
	"testing"

	"github.com/kforbus3/Moorgate/backend/internal/config"
)

func isolationCfg(on bool) *config.Config {
	return &config.Config{
		WGInterface:          "wgfleet",
		WGSubnet:             "10.100.0.0/24",
		WGJumpIP:             "10.100.0.1",
		WGPort:               51820,
		OverlayPeerIsolation: on,
	}
}

func TestHostAllowedIPs(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"isolated: the jump host alone", isolationCfg(true), "10.100.0.1/32"},
		{"not isolated: the historical whole subnet", isolationCfg(false), "10.100.0.0/24"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := (&Service{cfg: c.cfg}).hostAllowedIPs(); got != c.want {
				t.Errorf("hostAllowedIPs() = %q, want %q", got, c.want)
			}
		})
	}
}

// A jump IP that is not a plain address would render a config WireGuard refuses to
// parse, which takes the host's tunnel down completely. Falling back to the wide
// AllowedIPs loses the spoke-side half of the isolation — the hub-side deny still
// stands — which is much the lesser failure.
func TestHostAllowedIPsFallsBackOnUnusableJumpIP(t *testing.T) {
	for _, bad := range []string{"", "   ", "10.100.0.1/24", "jumphost", "10.100.0.999"} {
		cfg := isolationCfg(true)
		cfg.WGJumpIP = bad
		if got := (&Service{cfg: cfg}).hostAllowedIPs(); got != "10.100.0.0/24" {
			t.Errorf("WGJumpIP=%q: hostAllowedIPs() = %q, want the subnet fallback", bad, got)
		}
	}
}

// Both places the Linux script sets the peer — the wg-quick config and the
// wireguard-go fallback's `wg set` — must carry the same AllowedIPs. If they
// diverge, a host that lands on the fallback path is silently left wide open.
func TestHostWGScriptUsesAllowedIPsEverywhere(t *testing.T) {
	s := &Service{cfg: isolationCfg(true)}
	got := s.hostWGScript("10.100.0.24", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "jump.example.com:51820")

	if !strings.Contains(got, "ALLOWED=10.100.0.1/32") {
		t.Errorf("script does not set ALLOWED to the jump host's /32:\n%s", got)
	}
	if !strings.Contains(got, "AllowedIPs = $ALLOWED") {
		t.Error("wg-quick config does not use $ALLOWED")
	}
	if !strings.Contains(got, "allowed-ips $ALLOWED") {
		t.Error("the wireguard-go fallback path does not use $ALLOWED")
	}
	// The overlay subnet must not survive anywhere as a peer's AllowedIPs.
	if strings.Contains(got, "allowed-ips 10.100.0.0/24") || strings.Contains(got, "AllowedIPs = 10.100.0.0/24") {
		t.Errorf("script still grants the whole overlay subnet:\n%s", got)
	}
	// The interface address deliberately keeps its /24 — narrowing it changes
	// source-address selection on the host and buys no isolation.
	if !strings.Contains(got, "Address = $IP/24") {
		t.Error("interface address prefix changed; only AllowedIPs should have")
	}
}

func TestHostWGScriptWideWhenIsolationOff(t *testing.T) {
	s := &Service{cfg: isolationCfg(false)}
	got := s.hostWGScript("10.100.0.24", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "jump.example.com:51820")
	if !strings.Contains(got, "ALLOWED=10.100.0.0/24") {
		t.Errorf("isolation off should restore the whole-subnet AllowedIPs:\n%s", got)
	}
}

// The Windows tunnel config is generated from a separate template, so it can drift
// from the Linux one — it has before. Same host, same posture, same AllowedIPs.
func TestWindowsWGScriptCarriesAllowedIPs(t *testing.T) {
	s := &Service{cfg: isolationCfg(true)}
	got := windowsWGScript("10.100.0.24", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"jump.example.com:51820", s.hostAllowedIPs(), 51820)

	if !strings.Contains(got, "AllowedIPs = 10.100.0.1/32") {
		t.Errorf("Windows config does not pin AllowedIPs to the jump host:\n%s", got)
	}
	if strings.Contains(got, "__ALLOWEDIPS__") || strings.Contains(got, "__SUBNET__") {
		t.Error("Windows template left an unsubstituted placeholder")
	}
	if strings.Contains(got, "AllowedIPs = 10.100.0.0/24") {
		t.Error("Windows config still grants the whole overlay subnet")
	}
}
