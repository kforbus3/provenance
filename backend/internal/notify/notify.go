// Package notify delivers outbound alerts (email / webhook) for significant
// Fleet events: host offline/recovered, pending approvals, scan findings, and
// failed playbook runs. It is configured entirely through the `notifications`
// setting and is off until an operator enables a channel. Delivery is
// best-effort: a failure is logged and never blocks the action that triggered
// it.
package notify

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/store"
)

// Event types. Stable string keys — they also index Config.Events and appear in
// the settings UI.
const (
	EventHostOffline     = "host.offline"
	EventHostRecovered   = "host.recovered"
	EventApprovalPending = "approval.pending"
	EventScanFindings    = "scan.findings"
	EventPlaybookFailed  = "playbook.failed"
)

// AllEventTypes is the catalogue surfaced in the settings UI (key + label).
var AllEventTypes = []struct{ Key, Label string }{
	{EventHostOffline, "Host went offline"},
	{EventHostRecovered, "Host recovered"},
	{EventApprovalPending, "Access request pending approval"},
	{EventScanFindings, "Security scan found failures"},
	{EventPlaybookFailed, "Playbook run failed"},
}

const settingKey = "notifications"

// Severity is used to colour/shape outbound messages.
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// Event is a single notifiable occurrence.
type Event struct {
	Type     string
	Severity Severity
	Title    string
	Body     string
	// DedupeKey throttles repeats of the "same" event (e.g. a flapping host);
	// empty means no per-event throttling beyond the type.
	DedupeKey string
}

// EmailConfig configures a generic SMTP relay (any provider).
type EmailConfig struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	// Password is write-only from the API: callers send a plaintext value to
	// set it; it is stored encrypted in PasswordEnc and never returned.
	Password    string `json:"password,omitempty"`
	PasswordEnc string `json:"passwordEnc,omitempty"`
	From        string `json:"from"`
	To          string `json:"to"`
	Security    string `json:"security"` // starttls | tls | none
}

// WebhookConfig posts a JSON payload to a URL. Format shapes the body for
// common receivers.
type WebhookConfig struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
	Format  string `json:"format"` // json | slack | discord
}

// Route says which channels an event type goes to.
type Route struct {
	Email   bool `json:"email"`
	Webhook bool `json:"webhook"`
}

// Config is the persisted notification configuration.
type Config struct {
	Email           EmailConfig      `json:"email"`
	Webhook         WebhookConfig    `json:"webhook"`
	Events          map[string]Route `json:"events"`
	ThrottleMinutes int              `json:"throttleMinutes"`
}

// Service loads config from settings and dispatches events.
type Service struct {
	store *store.Store
	cfg   *config.Config
	log   *slog.Logger

	mu       sync.Mutex
	lastSent map[string]time.Time // dedupe key -> last delivery
}

func New(st *store.Store, cfg *config.Config, log *slog.Logger) *Service {
	return &Service{store: st, cfg: cfg, log: log, lastSent: map[string]time.Time{}}
}

// LoadConfig returns the stored config (zero value if unset).
func (s *Service) LoadConfig(ctx context.Context) (*Config, error) {
	raw, err := s.store.GetSetting(ctx, settingKey)
	if err != nil || len(raw) == 0 {
		return &Config{Events: map[string]Route{}}, nil
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return &Config{Events: map[string]Route{}}, nil
	}
	if c.Events == nil {
		c.Events = map[string]Route{}
	}
	return &c, nil
}

// Notify dispatches an event to whatever channels its type is routed to. It is
// safe to call from request handlers and goroutines; errors are logged only.
func (s *Service) Notify(ctx context.Context, ev Event) {
	cfg, err := s.LoadConfig(ctx)
	if err != nil {
		return
	}
	route := cfg.Events[ev.Type]
	if !route.Email && !route.Webhook {
		return
	}
	if !s.allow(ev, cfg) {
		return
	}
	if route.Email && cfg.Email.Enabled {
		if err := s.sendEmail(ctx, cfg, ev); err != nil {
			s.log.Warn("notify email failed", "event", ev.Type, "err", err)
		}
	}
	if route.Webhook && cfg.Webhook.Enabled {
		if err := s.sendWebhook(ctx, cfg, ev); err != nil {
			s.log.Warn("notify webhook failed", "event", ev.Type, "err", err)
		}
	}
}

// allow applies per-event throttling so repeats (e.g. a flapping host) don't
// spam. Default 5 minutes; configurable.
func (s *Service) allow(ev Event, cfg *Config) bool {
	if ev.DedupeKey == "" {
		return true
	}
	window := time.Duration(cfg.ThrottleMinutes) * time.Minute
	if window <= 0 {
		window = 5 * time.Minute
	}
	key := ev.Type + "|" + ev.DedupeKey
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.lastSent[key]; ok && time.Since(last) < window {
		return false
	}
	s.lastSent[key] = time.Now()
	return true
}
