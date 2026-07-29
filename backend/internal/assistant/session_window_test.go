package assistant

import "testing"

// "recently"/"lately" and a bare "who connected to X" (no time cue) all resolve to a
// one-week window; explicit windows and "who last connected" are unaffected.
func TestSessionHistoryIntentDefaultWindow(t *testing.T) {
	cases := []struct {
		q     string
		host  string
		hours int
		limit int
	}{
		{"has anyone connected to nas recently?", "nas", 168, 0},
		{"who connected to nas lately?", "nas", 168, 0},
		{"who connected to nas?", "nas", 168, 0},
		{"who connected to nas this month?", "nas", 720, 0},
		{"who connected to nas today?", "nas", 24, 0}, // calendar floor applied later at dispatch
		{"who last connected to nas?", "nas", 24 * 365, 1},
	}
	for _, c := range cases {
		host, hours, limit, ok := sessionHistoryIntent(c.q)
		if !ok {
			t.Fatalf("%q: expected fast-path match", c.q)
		}
		if host != c.host || hours != c.hours || limit != c.limit {
			t.Errorf("%q: got host=%q hours=%d limit=%d; want host=%q hours=%d limit=%d",
				c.q, host, hours, limit, c.host, c.hours, c.limit)
		}
	}
}

// calendarAdjustWindow leaves args alone when the question uses a rolling phrase (not a
// calendar one), when the args carry no "hours" field, and for single-row "last …"
// lookups (Limit==1). These guard paths return before any store/timezone lookup. (The
// actual calendar rewrites are exercised end-to-end by the live harness.)
func TestCalendarAdjustWindowGuards(t *testing.T) {
	s := &Service{}
	cases := []struct {
		name string
		q    string
		in   string
	}{
		{"rolling phrase passes through", "who connected to nas in the past week?", `{"hostname":"nas","hours":168}`},
		{"no hours field passes through", "which hosts have low disk today?", `{"maxDiskFreePct":20}`},
		{"limit==1 passes through", "who last connected to nas today?", `{"hostname":"nas","hours":24,"limit":1}`},
	}
	for _, c := range cases {
		if out := string(s.calendarAdjustWindow(nil, c.q, []byte(c.in))); out != c.in {
			t.Errorf("%s: got %s; want unchanged %s", c.name, out, c.in)
		}
	}
}
