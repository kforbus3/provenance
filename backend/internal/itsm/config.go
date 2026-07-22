package itsm

import (
	"context"
	"encoding/json"

	"github.com/fleet-terminal/backend/internal/secretbox"
	"github.com/fleet-terminal/backend/internal/store"
)

// SettingKey is the settings row that holds the ITSM configuration.
const SettingKey = "itsm"

// stored is the persisted shape; the token is sealed at rest (secretbox, keyed by the
// CA passphrase, like the other integration secrets) and never stored in plaintext.
type stored struct {
	Provider    string `json:"provider"`
	BaseURL     string `json:"baseUrl"`
	User        string `json:"user"`
	Project     string `json:"project"`
	Enabled     bool   `json:"enabled"`
	TokenSealed string `json:"tokenSealed"`
}

// LoadConfig reads and unseals the ITSM configuration. Returns a zero Config (not an
// error) when nothing is configured.
func LoadConfig(ctx context.Context, st *store.Store, caKey []byte) (Config, error) {
	raw, err := st.GetSetting(ctx, SettingKey)
	if err != nil || len(raw) == 0 {
		return Config{}, nil
	}
	var s stored
	if err := json.Unmarshal(raw, &s); err != nil {
		return Config{}, err
	}
	cfg := Config{Provider: s.Provider, BaseURL: s.BaseURL, User: s.User, Project: s.Project, Enabled: s.Enabled}
	if s.TokenSealed != "" {
		if pt, oerr := secretbox.Open(caKey, s.TokenSealed); oerr == nil {
			cfg.Token = string(pt)
		}
	}
	return cfg, nil
}

// SaveConfig seals the token and persists the configuration.
func SaveConfig(ctx context.Context, st *store.Store, caKey []byte, cfg Config) error {
	s := stored{Provider: cfg.Provider, BaseURL: cfg.BaseURL, User: cfg.User, Project: cfg.Project, Enabled: cfg.Enabled}
	if cfg.Token != "" {
		sealed, err := secretbox.Seal(caKey, []byte(cfg.Token))
		if err != nil {
			return err
		}
		s.TokenSealed = sealed
	}
	return st.SetSetting(ctx, SettingKey, s)
}
