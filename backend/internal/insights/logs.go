package insights

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/logsbroker"
	"github.com/kforbus3/provenance/backend/internal/models"
)

// Log-error spike thresholds. As with the rest of this package, deliberately
// simple: an operator can predict exactly when a card appears.
const (
	logRecentMinutes = 60     // the window called "now"
	logBaselineHours = 24 * 7 // ...compared with the week before it
	logMinPerHour    = 30     // absolute floor: below this, a spike is not worth a card
	logSpikeRatio    = 4.0    // ...and it must be this many times the baseline rate
	logMaxInsights   = 20     // cap, so one collector cannot flood the dashboard
)

// logRates is the slice of the log collector this package needs. An interface so
// the rules below can be tested without a collector, and so a deployment with no
// collector configured simply has no log insights.
type logRates interface {
	ErrorRates(ctx context.Context, recentMinutes, baselineHours int) ([]logsbroker.HostErrorRate, error)
}

// SetLogSource attaches the log collector, enabling the error-rate insight.
//
// It takes the concrete client rather than the interface on purpose: New returns a
// nil *Client when no collector is configured, and assigning that nil pointer
// straight into an interface field would produce a NON-NIL interface holding a nil
// pointer -- every Compute would then call through it and panic. Converting here,
// where the nil is visible, is the only place that trap can be closed.
func (s *Service) SetLogSource(c *logsbroker.Client) {
	if c == nil {
		s.logs = nil
		return
	}
	s.logs = c
}

// logInsights reports hosts whose error-log rate has jumped well above their own
// recent history.
//
// Their OWN history, not a fleet-wide number: a build server that logs 40 errors an
// hour every hour is not news, and a database that normally logs none is in trouble
// at five. Comparing each host with itself is what makes the card worth reading.
//
// A collector that is down or empty must not take the dashboard with it -- these
// insights are an addition to host metrics, not a precondition for them -- so every
// failure here returns nothing and logs.
func (s *Service) logInsights(ctx context.Context, hosts []models.Host, isSuperAdmin bool) []Insight {
	rates, err := s.logs.ErrorRates(ctx, logRecentMinutes, logBaselineHours)
	if err != nil {
		if !logsbroker.IsNoData(err) {
			s.log.Debug("log insights unavailable", "err", err)
		}
		return nil
	}

	// Index the hosts the caller can see, by every name a log line might carry.
	type ref struct {
		id            uuid.UUID
		hostname      string
		inMaintenance bool
	}
	byName := map[string]ref{}
	for i := range hosts {
		h := hosts[i]
		r := ref{id: h.ID, hostname: h.Hostname, inMaintenance: h.InMaintenance()}
		for _, n := range logNames(h) {
			if _, taken := byName[n]; !taken {
				byName[n] = r
			}
		}
	}

	out := []Insight{}
	for _, rate := range rates {
		title, detail, ok := logSpike(rate)
		if !ok {
			continue
		}
		h, known := byName[strings.ToLower(strings.TrimSpace(rate.Host))]
		switch {
		case known && h.inMaintenance:
			// Patching a host logs errors by design; it is silenced everywhere else
			// in this package and must be silenced here too.
			continue
		case known:
			out = append(out, insight(SeverityWarning, "logs", h.id, h.hostname, title, detail))
		case isSuperAdmin:
			// A sender with no matching host -- a switch, a firewall, an appliance
			// that ships syslog but Provenance does not manage. Worth surfacing,
			// but only to someone who can see the whole fleet, because there is no
			// host record to check access against.
			out = append(out, Insight{
				Severity: SeverityWarning, Category: "logs",
				Hostname: rate.Host, Title: title, Detail: detail,
			})
		}
		if len(out) >= logMaxInsights {
			break
		}
	}
	return out
}

// logNames returns the names a log line might carry for this host: its hostname, and
// the label before the first dot.
//
// Aldgate normalises senders to a short name, so a host enrolled as
// "hypervisor.example.com" arrives as "hypervisor" and would otherwise never match.
func logNames(h models.Host) []string {
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			out = append(out, s)
		}
	}
	add(h.Hostname)
	if i := strings.Index(h.Hostname, "."); i > 0 {
		add(h.Hostname[:i])
	}
	add(h.Address)
	return out
}

// logSpike applies the rule to one host's counts and writes the card's text.
//
// Both halves of the rule matter. The ratio alone would fire on a host that went
// from one error a day to six -- technically 6x, and nothing a person should be
// woken for. The floor alone would fire forever on a host that logs steadily and
// loudly, which is the fastest way to teach an operator to ignore the dashboard.
func logSpike(r logsbroker.HostErrorRate) (title, detail string, ok bool) {
	if r.RecentMinutes <= 0 || r.BaselineMinutes <= 0 {
		return "", "", false
	}
	perHour := float64(r.Recent) * 60 / float64(r.RecentMinutes)
	if perHour < logMinPerHour {
		return "", "", false
	}
	recentRate := float64(r.Recent) / float64(r.RecentMinutes) // per minute
	baseRate := float64(r.Baseline) / float64(r.BaselineMinutes)
	days := float64(r.BaselineMinutes) / (24 * 60)

	if r.Baseline == 0 {
		return "Logging errors", fmt.Sprintf(
			"%s in the last %s, and none at all in the %s before that.",
			plural(r.Recent, "error"), window(r.RecentMinutes), roundDays(days)), true
	}
	ratio := recentRate / baseRate
	if ratio < logSpikeRatio {
		return "", "", false
	}
	return "Logging errors", fmt.Sprintf(
		"%s in the last %s (%.1f/min) — %.0f× this host's %s average of %.2f/min.",
		plural(r.Recent, "error"), window(r.RecentMinutes), recentRate,
		ratio, roundDays(days), baseRate), true
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// window renders a minute count the way an operator would say it.
func window(minutes int) string {
	switch {
	case minutes%60 == 0 && minutes/60 == 1:
		return "hour"
	case minutes%60 == 0:
		return fmt.Sprintf("%d hours", minutes/60)
	default:
		return fmt.Sprintf("%d minutes", minutes)
	}
}

func roundDays(days float64) string {
	if days < 1.5 {
		return "24-hour"
	}
	return fmt.Sprintf("%.0f-day", days)
}
