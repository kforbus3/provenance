// Package digest sends a recurring fleet-health summary (daily or weekly) built
// from the same insights the dashboard and assistant use, delivered through the
// existing notification channels. It is off until an operator enables it, and
// deterministic — it needs no LLM, so the digest always sends even when Ollama is
// unavailable.
package digest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/insights"
	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/store"
)

const settingKey = "digest_policy"

// Policy is the persisted digest configuration. Delivery channels are controlled
// separately by routing the "fleet.digest" event in the notification settings;
// this policy only controls whether and when the digest is generated.
type Policy struct {
	Enabled   bool   `json:"enabled"`
	Frequency string `json:"frequency"` // daily | weekly
	Hour      int    `json:"hour"`      // 0-23, server local time
	Weekday   int    `json:"weekday"`   // 0=Sunday .. 6=Saturday (weekly only)
	LastSent  int64  `json:"lastSent"`  // unix seconds of the last delivery
}

func defaultPolicy() Policy {
	return Policy{Enabled: false, Frequency: "daily", Hour: 8, Weekday: 1}
}

// Service builds and sends digests on a schedule.
type Service struct {
	store    *store.Store
	insights *insights.Service
	notify   *notify.Service
	log      *slog.Logger
	now      func() time.Time // injectable for tests
}

func New(st *store.Store, ins *insights.Service, nfy *notify.Service, log *slog.Logger) *Service {
	return &Service{store: st, insights: ins, notify: nfy, log: log, now: time.Now}
}

// LoadPolicy returns the stored policy (defaults if unset), normalized.
func (s *Service) LoadPolicy(ctx context.Context) Policy {
	p := defaultPolicy()
	if raw, err := s.store.GetSetting(ctx, settingKey); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &p)
	}
	return normalize(p)
}

// SavePolicy persists the policy (preserving LastSent, which the loop owns).
func (s *Service) SavePolicy(ctx context.Context, p Policy) error {
	cur := s.LoadPolicy(ctx)
	p.LastSent = cur.LastSent
	return s.store.SetSetting(ctx, settingKey, normalize(p))
}

func normalize(p Policy) Policy {
	if p.Frequency != "weekly" {
		p.Frequency = "daily"
	}
	if p.Hour < 0 || p.Hour > 23 {
		p.Hour = 8
	}
	if p.Weekday < 0 || p.Weekday > 6 {
		p.Weekday = 1
	}
	return p
}

// Run drives the digest loop until ctx is cancelled, checking every 15 minutes
// whether the configured send time has arrived (and hasn't already fired today).
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tick(ctx)
		}
	}
}

func (s *Service) tick(ctx context.Context) {
	p := s.LoadPolicy(ctx)
	if !p.due(s.now()) {
		return
	}
	if err := s.send(ctx, p); err != nil {
		s.log.Warn("digest send", "err", err)
		return
	}
	p.LastSent = s.now().Unix()
	if err := s.store.SetSetting(ctx, settingKey, p); err != nil {
		s.log.Warn("digest save last-sent", "err", err)
	}
}

// due reports whether the digest should fire now: enabled, the hour matches, the
// weekday matches (weekly), and it hasn't already been sent today.
func (p Policy) due(now time.Time) bool {
	if !p.Enabled || now.Hour() != p.Hour {
		return false
	}
	if p.Frequency == "weekly" && int(now.Weekday()) != p.Weekday {
		return false
	}
	if p.LastSent > 0 {
		last := time.Unix(p.LastSent, 0)
		if last.Year() == now.Year() && last.YearDay() == now.YearDay() {
			return false // already sent today
		}
	}
	return true
}

// Preview builds the digest body without sending it (used by the "send test" and
// UI preview paths).
func (s *Service) Preview(ctx context.Context) (title, body string, sev notify.Severity, err error) {
	return s.build(ctx)
}

// SendNow builds and delivers a digest immediately, ignoring the schedule.
func (s *Service) SendNow(ctx context.Context) error {
	p := s.LoadPolicy(ctx)
	return s.send(ctx, p)
}

func (s *Service) send(ctx context.Context, _ Policy) error {
	title, body, sev, err := s.build(ctx)
	if err != nil {
		return err
	}
	s.notify.Notify(ctx, notify.Event{
		Type: notify.EventFleetDigest, Severity: sev, Title: title, Body: body,
	})
	return nil
}

// build assembles the digest from the whole fleet (super-admin scope) using the
// shared insights engine, and returns a severity reflecting the worst finding.
func (s *Service) build(ctx context.Context) (title, body string, sev notify.Severity, err error) {
	hosts, err := s.store.ListAccessibleHosts(ctx, uuid.Nil, true)
	if err != nil {
		return "", "", notify.SeverityInfo, err
	}
	online, offline := 0, 0
	for i := range hosts {
		switch {
		case hosts[i].Status != nil && hosts[i].Status.Status == "online":
			online++
		case hosts[i].Status != nil && hosts[i].Status.Status == "offline":
			offline++
		}
	}

	items, err := s.insights.Compute(ctx, uuid.Nil, true)
	if err != nil {
		return "", "", notify.SeverityInfo, err
	}
	var crit, warn []insights.Insight
	for _, it := range items {
		switch it.Severity {
		case insights.SeverityCritical:
			crit = append(crit, it)
		case insights.SeverityWarning:
			warn = append(warn, it)
		}
	}

	date := s.now().Format("Mon, Jan 2 2006")
	var b strings.Builder
	fmt.Fprintf(&b, "Fleet health digest — %s\n\n", date)
	fmt.Fprintf(&b, "Hosts: %d total, %d online, %d offline.\n", len(hosts), online, offline)
	fmt.Fprintf(&b, "Attention items: %d critical, %d warning.\n", len(crit), len(warn))

	if len(crit) == 0 && len(warn) == 0 {
		b.WriteString("\nNo issues detected — all monitored hosts look healthy.\n")
		return "Fleet health digest — all clear", b.String(), notify.SeverityInfo, nil
	}
	writeSection(&b, "CRITICAL", crit)
	writeSection(&b, "WARNING", warn)

	sev = notify.SeverityWarning
	titleSuffix := fmt.Sprintf("%d warning", len(warn))
	if len(crit) > 0 {
		sev = notify.SeverityError
		titleSuffix = fmt.Sprintf("%d critical", len(crit))
	}
	return "Fleet health digest — " + titleSuffix, b.String(), sev, nil
}

// writeSection appends a titled block, capped so a large fleet's digest stays
// readable; the overflow count is noted rather than silently dropped.
func writeSection(b *strings.Builder, title string, items []insights.Insight) {
	if len(items) == 0 {
		return
	}
	const limit = 20
	sort.SliceStable(items, func(i, j int) bool { return items[i].Hostname < items[j].Hostname })
	fmt.Fprintf(b, "\n%s\n", title)
	for i, it := range items {
		if i == limit {
			fmt.Fprintf(b, "  … and %d more\n", len(items)-limit)
			break
		}
		fmt.Fprintf(b, "  - %s — %s: %s\n", it.Hostname, it.Title, it.Detail)
	}
}
