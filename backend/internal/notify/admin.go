package notify

import (
	"context"
	"fmt"

	"github.com/fleet-terminal/backend/internal/secretbox"
)

// Save persists an incoming config. The SMTP password is encrypted at rest; if
// the incoming Password is blank the previously-stored secret is preserved (so
// the UI never has to round-trip it).
func (s *Service) Save(ctx context.Context, in *Config) error {
	cur, _ := s.LoadConfig(ctx)
	if in.Email.Password != "" {
		enc, err := secretbox.Seal(s.cfg.CAKeyPassphrase, []byte(in.Email.Password))
		if err != nil {
			return err
		}
		in.Email.PasswordEnc = enc
	} else {
		in.Email.PasswordEnc = cur.Email.PasswordEnc
	}
	in.Email.Password = "" // never persist plaintext
	// PagerDuty routing key + Opsgenie API key follow the same write-only,
	// encrypted-at-rest treatment as the SMTP password.
	if in.PagerDuty.RoutingKey != "" {
		enc, err := secretbox.Seal(s.cfg.CAKeyPassphrase, []byte(in.PagerDuty.RoutingKey))
		if err != nil {
			return err
		}
		in.PagerDuty.RoutingKeyEnc = enc
	} else {
		in.PagerDuty.RoutingKeyEnc = cur.PagerDuty.RoutingKeyEnc
	}
	in.PagerDuty.RoutingKey = ""
	if in.Opsgenie.APIKey != "" {
		enc, err := secretbox.Seal(s.cfg.CAKeyPassphrase, []byte(in.Opsgenie.APIKey))
		if err != nil {
			return err
		}
		in.Opsgenie.APIKeyEnc = enc
	} else {
		in.Opsgenie.APIKeyEnc = cur.Opsgenie.APIKeyEnc
	}
	in.Opsgenie.APIKey = ""
	if in.Events == nil {
		in.Events = map[string]Route{}
	}
	return s.store.SetSetting(ctx, settingKey, in)
}

// ResealSecrets re-seals this subsystem's at-rest secrets (SMTP password, PagerDuty
// routing key, Opsgenie API key) to the active KDF profile, in place, without needing
// the plaintext re-entered. It only rewrites settings if something changed. Returns
// the number of secrets upgraded. Used by the FIPS migration sweep.
func (s *Service) ResealSecrets(ctx context.Context) (int, error) {
	c, err := s.LoadConfig(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, f := range []*string{&c.Email.PasswordEnc, &c.PagerDuty.RoutingKeyEnc, &c.Opsgenie.APIKeyEnc} {
		out, changed, rerr := secretbox.ResealString(s.cfg.CAKeyPassphrase, *f)
		if rerr != nil {
			return n, rerr
		}
		if changed {
			*f = out
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	return n, s.store.SetSetting(ctx, settingKey, c)
}

// Redacted returns the config safe to send to the UI: no secret material, with a
// flag indicating whether a password is set.
type Redacted struct {
	Config
	PasswordSet     bool `json:"passwordSet"`
	PagerDutyKeySet bool `json:"pagerdutyKeySet"`
	OpsgenieKeySet  bool `json:"opsgenieKeySet"`
}

func (s *Service) Redacted(ctx context.Context) (*Redacted, error) {
	c, err := s.LoadConfig(ctx)
	if err != nil {
		return nil, err
	}
	r := &Redacted{
		Config:          *c,
		PasswordSet:     c.Email.PasswordEnc != "",
		PagerDutyKeySet: c.PagerDuty.RoutingKeyEnc != "",
		OpsgenieKeySet:  c.Opsgenie.APIKeyEnc != "",
	}
	r.Email.Password, r.Email.PasswordEnc = "", ""
	r.PagerDuty.RoutingKey, r.PagerDuty.RoutingKeyEnc = "", ""
	r.Opsgenie.APIKey, r.Opsgenie.APIKeyEnc = "", ""
	return r, nil
}

// SendTest delivers a sample message over a single channel, ignoring routing so
// an operator can verify a channel's settings. The settings being tested are
// taken from the stored config (save first, then test).
func (s *Service) SendTest(ctx context.Context, channel string) error {
	cfg, err := s.LoadConfig(ctx)
	if err != nil {
		return err
	}
	ev := Event{
		Type:     "test",
		Severity: SeverityInfo,
		Title:    "Fleet test notification",
		Body:     "This is a test notification from Fleet Terminal. If you received it, the channel is configured correctly.",
	}
	switch channel {
	case "email":
		if !cfg.Email.Enabled {
			return fmt.Errorf("email channel is disabled")
		}
		return s.sendEmail(ctx, cfg, ev, "")
	case "webhook":
		if !cfg.Webhook.Enabled {
			return fmt.Errorf("webhook channel is disabled")
		}
		return s.sendWebhook(ctx, cfg, ev)
	case "pagerduty":
		if !cfg.PagerDuty.Enabled {
			return fmt.Errorf("pagerduty channel is disabled")
		}
		return s.sendPagerDuty(ctx, cfg, ev)
	case "opsgenie":
		if !cfg.Opsgenie.Enabled {
			return fmt.Errorf("opsgenie channel is disabled")
		}
		return s.sendOpsgenie(ctx, cfg, ev)
	default:
		return fmt.Errorf("unknown channel %q", channel)
	}
}
