package ueba

import (
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
