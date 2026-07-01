package scan

import (
	"strings"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/models"
)

// controlPlaneTags mark a host as part of Fleet's own control plane. Remediating
// such a host can sever Fleet's access to the entire fleet, so the UI/API
// require an extra confirmation before applying fixes to it.
var controlPlaneTags = map[string]bool{"control-plane": true, "protected": true}

// isControlPlaneHost reports whether remediating this host risks locking Fleet
// out of the fleet. It is true when the host:
//   - carries a "control-plane" or "protected" tag,
//   - is explicitly listed in FLEET_CONTROL_PLANE_HOSTS, or
//   - matches the jump host's identity — remediating the SSH gateway breaks the
//     path to every managed host.
//
// It is intentionally a warning gate, not a hard block: an operator may still
// harden such a host deliberately, but not by accident.
func isControlPlaneHost(host *models.Host, cfg *config.Config) bool {
	if host == nil || cfg == nil {
		return false
	}
	for _, t := range host.Tags {
		if controlPlaneTags[strings.ToLower(strings.TrimSpace(t))] {
			return true
		}
	}
	// Identity strings that name THIS host.
	ids := map[string]bool{}
	for _, v := range []string{host.Hostname, host.Address, host.WGAddress} {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			ids[v] = true
		}
	}
	// Operator-declared control-plane hosts.
	for _, h := range cfg.ControlPlaneHosts {
		if ids[strings.ToLower(strings.TrimSpace(h))] {
			return true
		}
	}
	// The jump host (SSH gateway / WireGuard hub): breaking it breaks every host.
	for _, jh := range []string{hostPart(cfg.JumpHost), cfg.WGJumpIP, hostPart(cfg.WGJumpEndpoint)} {
		if jh = strings.ToLower(strings.TrimSpace(jh)); jh != "" && ids[jh] {
			return true
		}
	}
	return false
}

// hostPart strips a trailing :port from a "host:port" string. A value with no
// port (a bare hostname or a portless IPv4) is returned unchanged.
func hostPart(hp string) string {
	hp = strings.TrimSpace(hp)
	i := strings.LastIndex(hp, ":")
	if i < 0 {
		return hp
	}
	port := hp[i+1:]
	if port == "" {
		return hp
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return hp // not a port (e.g. an IPv6 literal) — leave as-is
		}
	}
	return hp[:i]
}
