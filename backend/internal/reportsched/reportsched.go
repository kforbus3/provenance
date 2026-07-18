// Package reportsched delivers compliance evidence reports (CSV) on a weekly or
// monthly cadence, via the existing notification channels — so "email the access
// report to compliance every month" is a set-and-forget setting. It reuses the
// same store exports as the on-demand Reports page and attaches the CSVs to the
// email. Off until an operator enables it.
package reportsched

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/store"
)

const settingKey = "report_schedule"

// reportKinds maps a report key to a human label + the store export it runs.
type reportDef struct {
	label  string
	export func(*store.Store, context.Context, time.Time, time.Time) (*store.ReportTable, error)
}

var reportKinds = map[string]reportDef{
	"access":       {"Access report", (*store.Store).ExportSSHSessions},
	"audit":        {"Audit trail", (*store.Store).ExportAuditEvents},
	"certificates": {"Certificate issuance", (*store.Store).ExportCertificates},
	"scans":        {"Scan posture", (*store.Store).ExportScans},
}

// Policy is the persisted schedule. Delivery channels are controlled separately
// by routing the "report.scheduled" event in notification settings.
type Policy struct {
	Enabled      bool     `json:"enabled"`
	Reports      []string `json:"reports"`      // subset of reportKinds
	Frequency    string   `json:"frequency"`    // weekly | monthly
	Weekday      int      `json:"weekday"`      // 0=Sun..6=Sat (weekly)
	DayOfMonth   int      `json:"dayOfMonth"`   // 1..28 (monthly)
	Hour         int      `json:"hour"`         // 0..23, server local time
	LookbackDays int      `json:"lookbackDays"` // window each report covers
	LastSent     int64    `json:"lastSent"`     // unix seconds of last delivery
}

func defaultPolicy() Policy {
	return Policy{
		Enabled: false, Reports: []string{"access", "audit"}, Frequency: "monthly",
		Weekday: 1, DayOfMonth: 1, Hour: 6, LookbackDays: 31,
	}
}

// Service builds and delivers scheduled reports.
type Service struct {
	store  *store.Store
	notify *notify.Service
	log    *slog.Logger
	now    func() time.Time
}

func New(st *store.Store, nfy *notify.Service, log *slog.Logger) *Service {
	return &Service{store: st, notify: nfy, log: log, now: time.Now}
}

func (s *Service) LoadPolicy(ctx context.Context) Policy {
	p := defaultPolicy()
	if raw, err := s.store.GetSetting(ctx, settingKey); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &p)
	}
	return normalize(p)
}

func (s *Service) SavePolicy(ctx context.Context, p Policy) error {
	cur := s.LoadPolicy(ctx)
	p.LastSent = cur.LastSent
	return s.store.SetSetting(ctx, settingKey, normalize(p))
}

func normalize(p Policy) Policy {
	if p.Frequency != "weekly" {
		p.Frequency = "monthly"
	}
	if p.Hour < 0 || p.Hour > 23 {
		p.Hour = 6
	}
	if p.Weekday < 0 || p.Weekday > 6 {
		p.Weekday = 1
	}
	if p.DayOfMonth < 1 || p.DayOfMonth > 28 {
		p.DayOfMonth = 1
	}
	if p.LookbackDays < 1 {
		p.LookbackDays = 31
	}
	kept := p.Reports[:0]
	for _, k := range p.Reports {
		if _, ok := reportKinds[k]; ok {
			kept = append(kept, k)
		}
	}
	p.Reports = kept
	return p
}

// Run drives the schedule, checking every 15 minutes whether a delivery is due.
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
		s.log.Warn("scheduled report send", "err", err)
		return
	}
	p.LastSent = s.now().Unix()
	if err := s.store.SetSetting(ctx, settingKey, p); err != nil {
		s.log.Warn("scheduled report save last-sent", "err", err)
	}
}

// due reports whether a delivery should fire now: enabled, hour matches, the
// weekday/day-of-month matches, at least one report selected, and not already
// sent today.
func (p Policy) due(now time.Time) bool {
	if !p.Enabled || len(p.Reports) == 0 || now.Hour() != p.Hour {
		return false
	}
	switch p.Frequency {
	case "weekly":
		if int(now.Weekday()) != p.Weekday {
			return false
		}
	default: // monthly
		if now.Day() != p.DayOfMonth {
			return false
		}
	}
	if p.LastSent > 0 {
		last := time.Unix(p.LastSent, 0)
		if last.Year() == now.Year() && last.YearDay() == now.YearDay() {
			return false
		}
	}
	return true
}

// SendNow generates and delivers the configured reports immediately.
func (s *Service) SendNow(ctx context.Context) error {
	return s.send(ctx, s.LoadPolicy(ctx))
}

func (s *Service) send(ctx context.Context, p Policy) error {
	to := s.now()
	from := to.AddDate(0, 0, -p.LookbackDays)
	var body strings.Builder
	fmt.Fprintf(&body, "Fleet compliance reports for %s to %s.\n\n",
		from.Format("2006-01-02"), to.Format("2006-01-02"))
	var attachments []notify.Attachment
	for _, kind := range p.Reports {
		def, ok := reportKinds[kind]
		if !ok {
			continue
		}
		table, err := def.export(s.store, ctx, from, to)
		if err != nil {
			s.log.Warn("scheduled report export", "report", kind, "err", err)
			fmt.Fprintf(&body, "- %s: FAILED to generate\n", def.label)
			continue
		}
		fmt.Fprintf(&body, "- %s: %d row(s) — attached\n", def.label, len(table.Rows))
		attachments = append(attachments, notify.Attachment{
			Filename:    fmt.Sprintf("fleet-%s-%s.csv", kind, to.Format("20060102")),
			ContentType: "text/csv",
			Data:        table.CSVBytes(),
		})
	}
	if len(attachments) == 0 {
		return fmt.Errorf("no reports generated")
	}
	s.notify.Notify(ctx, notify.Event{
		Type:        notify.EventReportScheduled,
		Severity:    notify.SeverityInfo,
		Title:       "Compliance reports — " + to.Format("Jan 2 2006"),
		Body:        body.String(),
		Attachments: attachments,
	})
	return nil
}
