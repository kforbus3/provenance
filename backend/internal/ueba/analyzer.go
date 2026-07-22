// Package ueba performs lightweight user-and-entity behavior analytics over Fleet's
// own access records (SSH/RDP sessions). It flags access patterns that deviate from a
// user's established baseline — off-hours access, first access to a host, a new source
// IP, and activity spikes — using simple, explainable statistics (no ML, no external
// dependency), matching Fleet's dependency-light, tamper-evident-audit ethos. The
// analyzer here is pure and unit-tested; the store fetches the sessions and the API
// surfaces the anomalies.
package ueba

import (
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// Session is one access record used for analysis.
type Session struct {
	UserID    uuid.UUID
	Username  string
	HostID    uuid.UUID
	Hostname  string
	IP        string
	StartedAt time.Time
}

// Anomaly is a flagged behavioral deviation.
type Anomaly struct {
	UserID   uuid.UUID `json:"userId"`
	Username string    `json:"username"`
	Type     string    `json:"type"`     // off_hours | new_host | new_source_ip | activity_spike
	Severity string    `json:"severity"` // info | warning
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
	Host     string    `json:"host,omitempty"`
	When     time.Time `json:"when"`
}

// minBaseline is the number of historical sessions a user needs before we flag
// deviations — otherwise brand-new users generate noise.
const minBaseline = 8

// Analyze returns anomalies found by comparing each user's recent activity (the last
// `recent` window ending at now) against their prior history. `sessions` may be in any
// order and span all users. Results are sorted most-recent first.
func Analyze(sessions []Session, now time.Time, recent time.Duration) []Anomaly {
	cutoff := now.Add(-recent)
	byUser := map[uuid.UUID][]Session{}
	for _, s := range sessions {
		byUser[s.UserID] = append(byUser[s.UserID], s)
	}

	var out []Anomaly
	for _, us := range byUser {
		out = append(out, analyzeUser(us, now, cutoff)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].When.After(out[j].When) })
	return out
}

func analyzeUser(sessions []Session, now, cutoff time.Time) []Anomaly {
	var history, recent []Session
	for _, s := range sessions {
		if s.StartedAt.Before(cutoff) {
			history = append(history, s)
		} else {
			recent = append(recent, s)
		}
	}
	if len(recent) == 0 || len(history) < minBaseline {
		return nil
	}

	// Baseline sets from history.
	hours := map[int]bool{}
	hosts := map[uuid.UUID]bool{}
	ips := map[string]bool{}
	var earliest time.Time
	for i, s := range history {
		hours[s.StartedAt.Hour()] = true
		hosts[s.HostID] = true
		if s.IP != "" {
			ips[s.IP] = true
		}
		if i == 0 || s.StartedAt.Before(earliest) {
			earliest = s.StartedAt
		}
	}

	u := recent[0]
	var out []Anomaly
	seenHost := map[uuid.UUID]bool{}
	seenIP := map[string]bool{}
	for _, s := range recent {
		if !hours[s.StartedAt.Hour()] {
			out = append(out, Anomaly{
				UserID: u.UserID, Username: u.Username, Type: "off_hours", Severity: "warning",
				Title:  "Access at an unusual hour",
				Detail: fmt.Sprintf("%s connected at %s, an hour outside their usual pattern.", u.Username, s.StartedAt.Format("15:04")),
				Host:   s.Hostname, When: s.StartedAt,
			})
		}
		if !hosts[s.HostID] && !seenHost[s.HostID] {
			seenHost[s.HostID] = true
			out = append(out, Anomaly{
				UserID: u.UserID, Username: u.Username, Type: "new_host", Severity: "info",
				Title:  "First access to a host",
				Detail: fmt.Sprintf("%s connected to %s for the first time.", u.Username, s.Hostname),
				Host:   s.Hostname, When: s.StartedAt,
			})
		}
		if s.IP != "" && !ips[s.IP] && !seenIP[s.IP] {
			seenIP[s.IP] = true
			out = append(out, Anomaly{
				UserID: u.UserID, Username: u.Username, Type: "new_source_ip", Severity: "warning",
				Title:  "New source IP",
				Detail: fmt.Sprintf("%s connected from %s, an address not seen before.", u.Username, s.IP),
				Host:   s.Hostname, When: s.StartedAt,
			})
		}
	}

	// Activity spike: recent count vs the user's historical daily average.
	days := now.Sub(earliest).Hours() / 24
	if days >= 1 {
		avgPerDay := float64(len(history)) / days
		threshold := 3 * avgPerDay
		if threshold < 5 {
			threshold = 5
		}
		if float64(len(recent)) > threshold {
			out = append(out, Anomaly{
				UserID: u.UserID, Username: u.Username, Type: "activity_spike", Severity: "warning",
				Title:  "Activity spike",
				Detail: fmt.Sprintf("%s started %d sessions recently vs a ~%.1f/day baseline.", u.Username, len(recent), avgPerDay),
				When:   now,
			})
		}
	}
	return out
}
