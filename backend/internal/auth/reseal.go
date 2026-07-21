package auth

import (
	"context"
	"encoding/json"

	"github.com/fleet-terminal/backend/internal/secretbox"
)

// ResealSecrets re-seals the auth subsystem's at-rest secrets (the LDAP bind password
// and the OIDC client secret) to the active KDF profile, in place, without needing them
// re-entered. It rewrites a setting only if its secret actually changed. Returns the
// number of secrets upgraded. Used by the FIPS migration sweep (`fleetctl fips
// reseal-secrets`).
func (s *Service) ResealSecrets(ctx context.Context) (int, error) {
	n := 0

	// LDAP bind password.
	if raw, err := s.store.GetSetting(ctx, ldapSettingKey); err == nil && len(raw) > 0 {
		var c ldapConfig
		if json.Unmarshal(raw, &c) == nil {
			out, changed, rerr := secretbox.ResealString(s.cfg.CAKeyPassphrase, c.BindPasswordEnc)
			if rerr != nil {
				return n, rerr
			}
			if changed {
				c.BindPasswordEnc = out
				if serr := s.store.SetSetting(ctx, ldapSettingKey, c); serr != nil {
					return n, serr
				}
				n++
			}
		}
	}

	// OIDC client secret.
	if raw, err := s.store.GetSetting(ctx, oidcSettingKey); err == nil && len(raw) > 0 {
		var c oidcConfig
		if json.Unmarshal(raw, &c) == nil {
			out, changed, rerr := secretbox.ResealString(s.cfg.CAKeyPassphrase, c.SecretEnc)
			if rerr != nil {
				return n, rerr
			}
			if changed {
				c.SecretEnc = out
				if serr := s.store.SetSetting(ctx, oidcSettingKey, c); serr != nil {
					return n, serr
				}
				n++
			}
		}
	}

	return n, nil
}
