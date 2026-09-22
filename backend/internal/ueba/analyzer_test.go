package ueba

import (
	"regexp"
	"testing"
	"time"

	"github.com/google/uuid"
)

func baselineSessions(user uuid.UUID, host uuid.UUID, ip string, n int, now time.Time) []Session {
	var out []Session
	for i := 0; i < n; i++ {
		day := now.AddDate(0, 0, -(i + 2))
		hour := 9 + (i % 8) // business hours 09:00–16:00, spread over prior days
		ts := time.Date(day.Year(), day.Month(), day.Day(), hour, 0, 0, 0, time.UTC)
		out = append(out, Session{
			UserID: user, Username: "alice", HostID: host, Hostname: "web-01", IP: ip, StartedAt: ts,
		})
	}
	return out
}

func hasType(as []Anomaly, t string) bool {
	for _, a := range as {
		if a.Type == t {
			return true
		}
	}
	return false
}

func TestNoAnomaliesWithoutBaseline(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	user, host := uuid.New(), uuid.New()
	// Only 3 historical sessions (< minBaseline) + one recent → no anomalies.
	s := baselineSessions(user, host, "10.0.0.1", 3, now)
	s = append(s, Session{UserID: user, Username: "alice", HostID: host, Hostname: "web-01", IP: "10.0.0.1", StartedAt: now.Add(-time.Hour)})
	if got := Analyze(s, now, 24*time.Hour); len(got) != 0 {
		t.Errorf("expected no anomalies without baseline, got %d: %+v", len(got), got)
	}
}

func TestOffHoursAndNewHostAndNewIP(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	user, host, other := uuid.New(), uuid.New(), uuid.New()
	s := baselineSessions(user, host, "10.0.0.1", 12, now)
	// Recent: 03:00 (off-hours), to a NEW host, from a NEW ip.
	s = append(s, Session{
		UserID: user, Username: "alice", HostID: other, Hostname: "db-99", IP: "203.0.113.5",
		StartedAt: now.Add(-9 * time.Hour), // 03:00
	})
	got := Analyze(s, now, 24*time.Hour)
	if !hasType(got, "off_hours") {
		t.Error("expected off_hours anomaly")
	}
	if !hasType(got, "new_host") {
		t.Error("expected new_host anomaly")
	}
	if !hasType(got, "new_source_ip") {
		t.Error("expected new_source_ip anomaly")
	}
}

func TestNoAnomalyForNormalActivity(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	user, host := uuid.New(), uuid.New()
	s := baselineSessions(user, host, "10.0.0.1", 12, now)
	// Recent session at a usual hour, known host, known ip.
	s = append(s, Session{UserID: user, Username: "alice", HostID: host, Hostname: "web-01", IP: "10.0.0.1", StartedAt: now.Add(-2 * time.Hour)})
	got := Analyze(s, now, 24*time.Hour)
	if len(got) != 0 {
		t.Errorf("expected no anomalies for normal activity, got %+v", got)
	}
}

func TestActivitySpike(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	user, host := uuid.New(), uuid.New()
	s := baselineSessions(user, host, "10.0.0.1", 12, now) // ~ modest baseline
	// 20 recent sessions (all normal hour/host/ip) → volume spike.
	for i := 0; i < 20; i++ {
		s = append(s, Session{UserID: user, Username: "alice", HostID: host, Hostname: "web-01", IP: "10.0.0.1",
			StartedAt: now.Add(-time.Duration(i*10) * time.Minute).Add(-2 * time.Hour)})
	}
	if !hasType(Analyze(s, now, 24*time.Hour), "activity_spike") {
		t.Error("expected activity_spike anomaly")
	}
}

// TestDetailCarriesNoWallClock is the regression guard for a Behavior-page report: each
// event's prose named a time that disagreed with the timestamp rendered beside it.
//
// Both came from the same instant. The prose was formatted server-side with no zone,
// while the stamp goes through the UI's formatter, which applies the configured display
// timezone (or the browser's) — so they differed by the server-to-viewer offset. A
// timestamp belongs to whoever renders it; Anomaly.When carries the instant.
//
// This fails if any anomaly's Detail regains an embedded clock time.
func TestDetailCarriesNoWallClock(t *testing.T) {
	// A session at 23:00 UTC against a 09:00–16:00 baseline: off-hours fires, and a
	// naive formatter would write "23:00" into the sentence.
	now := time.Date(2026, 7, 20, 23, 30, 0, 0, time.UTC)
	user, host, other := uuid.New(), uuid.New(), uuid.New()
	s := baselineSessions(user, host, "10.0.0.1", minBaseline+2, now)
	s = append(s, Session{
		UserID: user, Username: "alice", HostID: other, Hostname: "db-01",
		IP: "10.9.9.9", StartedAt: time.Date(2026, 7, 20, 23, 0, 0, 0, time.UTC),
	})

	got := Analyze(s, now, 24*time.Hour)
	if len(got) == 0 {
		t.Fatal("precondition: expected at least one anomaly to inspect")
	}
	if !hasType(got, "off_hours") {
		t.Fatal("precondition: expected the off_hours anomaly, which is the one that named a time")
	}

	// Any HH:MM in the prose is the defect, whatever the zone it was rendered in.
	clock := regexp.MustCompile(`\b([01]?\d|2[0-3]):[0-5]\d\b`)
	for _, a := range got {
		if m := clock.FindString(a.Detail); m != "" {
			t.Errorf("anomaly %q embeds the wall-clock time %q in Detail: %q\n"+
				"the viewer renders When in their own zone, so a time formatted here "+
				"contradicts the stamp shown next to it", a.Type, m, a.Detail)
		}
		if a.When.IsZero() {
			t.Errorf("anomaly %q has no When for the caller to render", a.Type)
		}
	}
}

// TestOffHoursDetectionIsZoneInvariant records why only the DISPLAY was wrong. The
// baseline hours and the test against them are both derived from StartedAt, so moving
// every session into another zone rotates all the hour buckets uniformly and cannot
// change which hours count as usual. Detection needed no fix; had this failed, the
// report would have been about wrong findings rather than wrong labels.
func TestOffHoursDetectionIsZoneInvariant(t *testing.T) {
	now := time.Date(2026, 7, 20, 23, 30, 0, 0, time.UTC)
	user, host, other := uuid.New(), uuid.New(), uuid.New()
	build := func(loc *time.Location) []Anomaly {
		s := baselineSessions(user, host, "10.0.0.1", minBaseline+2, now)
		s = append(s, Session{
			UserID: user, Username: "alice", HostID: other, Hostname: "db-01",
			IP: "10.9.9.9", StartedAt: time.Date(2026, 7, 20, 23, 0, 0, 0, time.UTC),
		})
		for i := range s {
			s[i].StartedAt = s[i].StartedAt.In(loc)
		}
		return Analyze(s, now.In(loc), 24*time.Hour)
	}
	utc := build(time.UTC)
	east := build(time.FixedZone("UTC-5", -5*3600))
	if hasType(utc, "off_hours") != hasType(east, "off_hours") {
		t.Errorf("off_hours detection changed with the zone: utc=%v shifted=%v",
			hasType(utc, "off_hours"), hasType(east, "off_hours"))
	}
	if len(utc) != len(east) {
		t.Errorf("anomaly count changed with the zone: utc=%d shifted=%d", len(utc), len(east))
	}
}
