// Package insights derives explainable, at-a-glance fleet-health observations
// from the data the monitor already collects — current host status/metrics plus
// the metric-history time series — with no ML dependency. It powers the Ask-AI
// "what's wrong?" story and the dashboard insight cards. Everything is scoped to
// the hosts the caller can access.
package insights

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/store"
)

// Severity levels, ordered most-urgent first for ranking.
const (
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
	SeverityInfo     = "info"
)

// Thresholds. Deliberately simple and explainable — an operator can predict
// exactly when a card appears.
const (
	diskCriticalPct   = 5   // free % at/under which disk is critical
	diskWarningPct    = 15  // free % at/under which disk is a warning
	diskRunwayScanPct = 50  // only project runway for hosts below this free %
	memWarningPct     = 92  // used % over which memory is a warning
	loadWarningPerCPU = 2.0 // load-per-core over which CPU is a warning
	runwayWarnDays    = 14  // project-full horizon that warrants a warning
	runwayCritDays    = 3   // ...and a critical
	minDailyDecline   = 0.1 // %/day of disk decline below which trend is noise
	maxRunwayAnalyses = 50  // cap per-host history queries per computation
)

// Insight is one surfaced observation about a host.
type Insight struct {
	Severity string `json:"severity"` // critical|warning|info
	Category string `json:"category"` // offline|disk|disk-runway|memory|load|updates
	HostID   string `json:"hostId"`
	Hostname string `json:"hostname"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

// Service computes insights from the store.
type Service struct {
	store           *store.Store
	log             *slog.Logger
	metricRetention time.Duration // 0 = history disabled → runway projection skipped
}

func New(st *store.Store, log *slog.Logger, metricRetention time.Duration) *Service {
	return &Service{store: st, log: log, metricRetention: metricRetention}
}

// Compute returns the current insights for the hosts the user can access, ranked
// most-urgent first.
func (s *Service) Compute(ctx context.Context, userID uuid.UUID, isSuperAdmin bool) ([]Insight, error) {
	hosts, err := s.store.ListAccessibleHosts(ctx, userID, isSuperAdmin)
	if err != nil {
		return nil, err
	}
	out := []Insight{}
	type ref struct {
		id       uuid.UUID
		hostname string
		freePct  float64
	}
	var runwayCandidates []ref

	for i := range hosts {
		h := hosts[i]
		// Offline hosts: one clear card; skip stale metric checks on them.
		if h.Status != nil && h.Status.Status == "offline" {
			detail := "Fleet can no longer reach this host over SSH."
			if h.Status.LastSuccessAt != nil {
				detail = "Last reachable " + h.Status.LastSuccessAt.Format("Jan 2 15:04") + "."
			}
			out = append(out, Insight{
				Severity: SeverityWarning, Category: "offline",
				HostID: h.ID.String(), Hostname: h.Hostname,
				Title: "Host offline", Detail: detail,
			})
			continue
		}
		m := h.Metrics
		if m == nil {
			continue
		}
		if m.MinDiskFreePct != nil {
			free := *m.MinDiskFreePct
			switch {
			case free <= diskCriticalPct:
				out = append(out, insight(SeverityCritical, "disk", h.ID, h.Hostname,
					"Disk almost full", fmt.Sprintf("Only %.0f%% free on the tightest filesystem.", free)))
			case free <= diskWarningPct:
				out = append(out, insight(SeverityWarning, "disk", h.ID, h.Hostname,
					"Low disk space", fmt.Sprintf("%.0f%% free on the tightest filesystem.", free)))
			}
			if free <= diskRunwayScanPct {
				runwayCandidates = append(runwayCandidates, ref{h.ID, h.Hostname, free})
			}
		}
		if m.MemUsedPct != nil && *m.MemUsedPct >= memWarningPct {
			out = append(out, insight(SeverityWarning, "memory", h.ID, h.Hostname,
				"High memory use", fmt.Sprintf("%.0f%% of memory in use.", *m.MemUsedPct)))
		}
		if m.LoadPerCore != nil && *m.LoadPerCore >= loadWarningPerCPU {
			out = append(out, insight(SeverityWarning, "load", h.ID, h.Hostname,
				"High CPU load", fmt.Sprintf("Load per core is %.2f (>= %.1f).", *m.LoadPerCore, loadWarningPerCPU)))
		}
		if h.Inventory != nil && h.Inventory.SecurityUpdates != nil && *h.Inventory.SecurityUpdates > 0 {
			out = append(out, insight(SeverityWarning, "updates", h.ID, h.Hostname,
				"Security updates pending", fmt.Sprintf("%d security update(s) available.", *h.Inventory.SecurityUpdates)))
		}
	}

	// Disk-runway projection for at-risk hosts (bounded), only when history exists.
	if s.metricRetention > 0 && len(runwayCandidates) > 0 {
		// Analyze the lowest-disk hosts first, capped, so this stays cheap.
		sort.Slice(runwayCandidates, func(a, b int) bool {
			return runwayCandidates[a].freePct < runwayCandidates[b].freePct
		})
		if len(runwayCandidates) > maxRunwayAnalyses {
			runwayCandidates = runwayCandidates[:maxRunwayAnalyses]
		}
		for _, c := range runwayCandidates {
			days, conf, ok := s.diskRunwayDays(ctx, c.id)
			if !ok || days > runwayWarnDays {
				continue
			}
			sev := SeverityWarning
			if days <= runwayCritDays {
				sev = SeverityCritical
			}
			out = append(out, insight(sev, "disk-runway", c.id, c.hostname,
				"Disk filling up", fmt.Sprintf("At the recent rate, the tightest filesystem fills in ~%.0f day(s) (%s confidence).", days, conf)))
		}
	}

	sort.SliceStable(out, func(a, b int) bool {
		return severityRank(out[a].Severity) < severityRank(out[b].Severity)
	})
	return out, nil
}

func insight(sev, cat string, id uuid.UUID, hostname, title, detail string) Insight {
	return Insight{Severity: sev, Category: cat, HostID: id.String(), Hostname: hostname, Title: title, Detail: detail}
}

func severityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityWarning:
		return 1
	default:
		return 2
	}
}

// diskRunwayDays estimates days until the tightest filesystem fills, by fitting a
// least-squares line to the last week of disk-free samples. It returns the
// estimate, a confidence label derived from how well the line fits the data (R²:
// a steady decline reads high, a noisy one low), and ok=false for a flat/rising
// trend that isn't filling up at all.
func (s *Service) diskRunwayDays(ctx context.Context, hostID uuid.UUID) (days float64, confidence string, ok bool) {
	since := time.Now().Add(-7 * 24 * time.Hour)
	pts, err := s.store.MetricHistory(ctx, hostID, since, time.Hour)
	if err != nil || len(pts) < 4 {
		return 0, "", false
	}
	var xs, ys []float64
	t0 := pts[0].Time
	for _, p := range pts {
		if p.DiskFreePctAvg == nil {
			continue
		}
		xs = append(xs, p.Time.Sub(t0).Hours()/24)
		ys = append(ys, *p.DiskFreePctAvg)
	}
	if len(xs) < 4 {
		return 0, "", false
	}
	slope, intercept, r2, fit := linreg(xs, ys)
	if !fit {
		return 0, "", false
	}
	dailyDecline := -slope // positive when disk free is falling
	if dailyDecline < minDailyDecline {
		return 0, "", false // flat or rising: not filling up
	}
	conf := "low"
	switch {
	case r2 >= 0.75:
		conf = "high"
	case r2 >= 0.4:
		conf = "medium"
	}
	lastX := xs[len(xs)-1]
	projectedFree := slope*lastX + intercept
	if projectedFree <= 0 {
		return 0, conf, true // already effectively full
	}
	return projectedFree / dailyDecline, conf, true
}

// linreg returns the least-squares slope, intercept, and coefficient of
// determination (R², 0..1) of y over x. ok is false when x has no variance (a
// vertical fit is undefined).
func linreg(xs, ys []float64) (slope, intercept, r2 float64, ok bool) {
	n := float64(len(xs))
	var sx, sy, sxx, sxy float64
	for i := range xs {
		sx += xs[i]
		sy += ys[i]
		sxx += xs[i] * xs[i]
		sxy += xs[i] * ys[i]
	}
	denom := n*sxx - sx*sx
	if denom == 0 {
		return 0, 0, 0, false
	}
	slope = (n*sxy - sx*sy) / denom
	intercept = (sy - slope*sx) / n
	// R² = 1 - SS_res/SS_tot.
	mean := sy / n
	var ssRes, ssTot float64
	for i := range xs {
		pred := slope*xs[i] + intercept
		ssRes += (ys[i] - pred) * (ys[i] - pred)
		ssTot += (ys[i] - mean) * (ys[i] - mean)
	}
	if ssTot > 0 {
		r2 = 1 - ssRes/ssTot
	} else {
		r2 = 1 // perfectly flat y that still passed the variance check
	}
	return slope, intercept, r2, true
}
