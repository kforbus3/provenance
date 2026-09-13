package store

import (
	"context"
	"encoding/json"
	"fmt"
)

// WireGuardSettings is the operator-configurable VPN (jump host) endpoint that
// managed hosts dial, stored in the settings table under key "wireguard".
type WireGuardSettings struct {
	JumpHost string `json:"jumpHost"`
	JumpPort int    `json:"jumpPort"`
}

// GetWireGuardSettings reads the configured VPN endpoint from settings.
func (s *Store) GetWireGuardSettings(ctx context.Context) (WireGuardSettings, bool) {
	raw, err := s.GetSetting(ctx, "wireguard")
	if err != nil || len(raw) == 0 {
		return WireGuardSettings{}, false
	}
	var v WireGuardSettings
	if json.Unmarshal(raw, &v) != nil || v.JumpHost == "" {
		return WireGuardSettings{}, false
	}
	if v.JumpPort == 0 {
		v.JumpPort = 51820
	}
	return v, true
}

// WireGuardEndpoint returns the configured "host:port" jump endpoint, or "" if
// unset. Callers fall back to the PROV_WG_JUMP_ENDPOINT config default.
func (s *Store) WireGuardEndpoint(ctx context.Context) string {
	if v, ok := s.GetWireGuardSettings(ctx); ok {
		return fmt.Sprintf("%s:%d", v.JumpHost, v.JumpPort)
	}
	return ""
}
