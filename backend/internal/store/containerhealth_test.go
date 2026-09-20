package store

import "testing"

// Which containers are worth reporting, and which are ordinary.
//
// The temptation is to list everything that is not "running". That version gets
// ignored, because a compose project routinely contains one-shot containers that
// have exited 0 and should have -- and once the list is noise, the crash loop
// underneath it is invisible again for a new reason.
func TestWhatCountsAsAContainerProblem(t *testing.T) {
	cases := []struct {
		name   string
		state  string
		status string
		report bool
	}{
		// The two that were live in production while nothing said so.
		{"crash loop exiting zero", "restarting", "Restarting (0) 40 seconds ago", true},
		{"crash loop exiting one", "restarting", "Restarting (1) 50 seconds ago", true},

		{"dead", "dead", "Dead", true},
		{"paused", "paused", "Paused", true},
		{"exited with a failure", "exited", "Exited (137) 2 hours ago", true},

		// A finished job. Reporting this is what makes the list unreadable.
		{"one-shot that completed", "exited", "Exited (0) 3 hours ago", false},

		// Up, and not working. Docker leaves the state as "running" and puts this
		// in the status alone, so a check on state misses exactly the container a
		// healthcheck exists to find.
		{"running but unhealthy", "running", "Up 2 days (unhealthy)", true},

		{"healthy", "running", "Up 2 days (healthy)", false},
		{"plain running", "running", "Up 6 minutes", false},
		{"starting up", "running", "Up 3 seconds (health: starting)", false},

		// Transient states a single collection cannot interpret. A warning that
		// clears itself teaches people to wait rather than look.
		{"created", "created", "Created", false},
		{"removing", "removing", "Removal In Progress", false},
	}
	for _, c := range cases {
		why, report := whyUnhealthy(c.state, c.status)
		if report != c.report {
			t.Errorf("%s (%s / %q): reported=%v, want %v", c.name, c.state, c.status, report, c.report)
			continue
		}
		if report && why == "" {
			t.Errorf("%s: reported with no reason given", c.name)
		}
	}
}

func TestExitCodeIsReadFromTheStatusLine(t *testing.T) {
	cases := []struct {
		status string
		want   int
		ok     bool
	}{
		{"exited (0) 3 hours ago", 0, true},
		{"exited (137) 2 hours ago", 137, true},
		{"restarting (0) 40 seconds ago", 0, true},
		{"up 2 days", 0, false},
		{"exited (unknown) ago", 0, false},
		{"exited (", 0, false},
	}
	for _, c := range cases {
		got, ok := exitCode(c.status)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("exitCode(%q) = (%d, %v), want (%d, %v)", c.status, got, ok, c.want, c.ok)
		}
	}
}
