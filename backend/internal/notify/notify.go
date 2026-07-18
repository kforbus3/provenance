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
	EventHostOffline      = "host.offline"
	EventHostRecovered    = "host.recovered"
	EventApprovalPending  = "approval.pending"
	EventApprovalResolved = "approval.resolved"
	EventAccessExpired    = "access.expired"
	EventScanFindings     = "scan.findings"
	EventPlaybookFailed   = "playbook.failed"
	EventCAKeyAging       = "ca.aging"
	EventFleetDigest      = "fleet.digest"
	EventReportScheduled  = "report.scheduled"
)

// AllEventTypes is the catalogue surfaced in the settings UI (key + label). The
// routing configured here controls delivery; for events that concern a specific
// user (resolution, expiry), enabling the Email route also emails that user
// directly at their profile address (see Event.Recipient).
var AllEventTypes = []struct{ Key, Label string }{
	{EventHostOffline, "Host went offline"},
	{EventHostRecovered, "Host recovered"},
	{EventApprovalPending, "Access request pending approval"},
	{EventApprovalResolved, "Access request approved or denied"},
	{EventAccessExpired, "Just-in-time access expired"},
	{EventScanFindings, "Security scan found failures"},
	{EventPlaybookFailed, "Playbook run failed"},
	{EventCAKeyAging, "CA key due for rotation"},
	{EventFleetDigest, "Scheduled fleet-health digest"},
	{EventReportScheduled, "Scheduled compliance report"},
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
	// Recipient, when set, is a direct email address the event also goes to (the
	// user it concerns, e.g. an approval requester). It is delivered when the event
	// is routed to email — the same gate as the admin distribution — so disabling
	// the event's email route silences both.
	Recipient string
	// Attachments are files delivered with the event. They are attached to email
	// (multipart/mixed); the webhook channel ignores them (it sends the Body only).
	Attachments []Attachment
}

// Attachment is a file delivered alongside an email event.
type Attachment struct {
	Filename    string
	ContentType string // e.g. "text/csv"; defaults to application/octet-stream
	Data        []byte
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
	Format  string `json:"format"` // json | slack | discord | teams
}

// PagerDutyConfig pages via the Events API v2. It is severity-gated (not
// per-event): every event at or above MinSeverity triggers an incident, which is
// how on-call tooling is normally driven. The routing key is stored encrypted.
type PagerDutyConfig struct {
	Enabled       bool     `json:"enabled"`
	RoutingKey    string   `json:"routingKey,omitempty"` // write-only input
	RoutingKeyEnc string   `json:"routingKeyEnc,omitempty"`
	MinSeverity   Severity `json:"minSeverity"` // info|warning|error (default warning)
}

// OpsgenieConfig raises alerts via the Opsgenie Alerts API, severity-gated like
// PagerDuty. The API key is stored encrypted; Region selects the US or EU host.
type OpsgenieConfig struct {
	Enabled     bool     `json:"enabled"`
	APIKey      string   `json:"apiKey,omitempty"` // write-only input
	APIKeyEnc   string   `json:"apiKeyEnc,omitempty"`
	Region      string   `json:"region"` // us | eu
	MinSeverity Severity `json:"minSeverity"`
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
	PagerDuty       PagerDutyConfig  `json:"pagerduty"`
	Opsgenie        OpsgenieConfig   `json:"opsgenie"`
	Events          map[string]Route `json:"events"`
	ThrottleMinutes int              `json:"throttleMinutes"`
}

// severityRank orders severities for the incident-channel minimum-severity gate.
func severityRank(s Severity) int {
	switch s {
	case SeverityError:
		return 2
	case SeverityWarning:
		return 1
	default:
		return 0
	}
}

// meetsMinSeverity reports whether ev is at least as severe as min (empty min
// defaults to warning, so info-level events don't page by default).
func meetsMinSeverity(ev, min Severity) bool {
	if min == "" {
		min = SeverityWarning
	}
	return severityRank(ev) >= severityRank(min)
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
	adminEmail := route.Email && cfg.Email.Enabled
	adminWebhook := route.Webhook && cfg.Webhook.Enabled
	// A direct recipient is emailed only when this event is routed to email — same
	// gate as the admin distribution, so disabling the event silences both.
	directEmail := ev.Recipient != "" && route.Email && cfg.Email.Enabled
	// Incident channels are severity-gated rather than per-event: they fire on any
	// event at or above their minimum severity.
	pageDuty := cfg.PagerDuty.Enabled && meetsMinSeverity(ev.Severity, cfg.PagerDuty.MinSeverity)
	pageOpsgenie := cfg.Opsgenie.Enabled && meetsMinSeverity(ev.Severity, cfg.Opsgenie.MinSeverity)
	if !adminEmail && !adminWebhook && !directEmail && !pageDuty && !pageOpsgenie {
		return
	}
	if !s.allow(ev, cfg) {
		return
	}
	if adminEmail {
		if err := s.sendEmail(ctx, cfg, ev, ""); err != nil {
			s.log.Warn("notify email failed", "event", ev.Type, "err", err)
		}
	}
	if directEmail {
		if err := s.sendEmail(ctx, cfg, ev, ev.Recipient); err != nil {
			s.log.Warn("notify recipient email failed", "event", ev.Type, "err", err)
		}
	}
	if adminWebhook {
		if err := s.sendWebhook(ctx, cfg, ev); err != nil {
			s.log.Warn("notify webhook failed", "event", ev.Type, "err", err)
		}
	}
	if pageDuty {
		if err := s.sendPagerDuty(ctx, cfg, ev); err != nil {
			s.log.Warn("notify pagerduty failed", "event", ev.Type, "err", err)
		}
	}
	if pageOpsgenie {
		if err := s.sendOpsgenie(ctx, cfg, ev); err != nil {
			s.log.Warn("notify opsgenie failed", "event", ev.Type, "err", err)
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
