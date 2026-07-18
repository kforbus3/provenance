package reports

import "testing"

func TestParseDate(t *testing.T) {
	// Bare date: start-of-day, and exclusive end (next day) when endOfDay.
	from, ok := parseDate("2026-07-01", false)
	if !ok || from.Format("2006-01-02T15:04:05Z07:00") != "2026-07-01T00:00:00Z" {
		t.Fatalf("from = %v ok=%v", from, ok)
	}
	to, ok := parseDate("2026-07-01", true)
	if !ok || to.Format("2006-01-02") != "2026-07-02" {
		t.Fatalf("endOfDay upper bound should be the next day, got %v", to)
	}

	// RFC3339 passes through unchanged (to UTC).
	rfc, ok := parseDate("2026-07-01T12:30:00Z", false)
	if !ok || rfc.Hour() != 12 || rfc.Minute() != 30 {
		t.Fatalf("rfc parse = %v ok=%v", rfc, ok)
	}

	if _, ok := parseDate("not-a-date", false); ok {
		t.Fatal("garbage should not parse")
	}
}
