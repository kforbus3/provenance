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
	if in.Events == nil {
		in.Events = map[string]Route{}
	}
	return s.store.SetSetting(ctx, settingKey, in)
}

// Redacted returns the config safe to send to the UI: no secret material, with a
// flag indicating whether a password is set.
type Redacted struct {
	Config
	PasswordSet bool `json:"passwordSet"`
}

func (s *Service) Redacted(ctx context.Context) (*Redacted, error) {
	c, err := s.LoadConfig(ctx)
	if err != nil {
		return nil, err
	}
	r := &Redacted{Config: *c, PasswordSet: c.Email.PasswordEnc != ""}
	r.Email.Password = ""
	r.Email.PasswordEnc = ""
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
		return s.sendEmail(ctx, cfg, ev)
	case "webhook":
		if !cfg.Webhook.Enabled {
			return fmt.Errorf("webhook channel is disabled")
		}
		return s.sendWebhook(ctx, cfg, ev)
	default:
		return fmt.Errorf("unknown channel %q", channel)
	}
}
