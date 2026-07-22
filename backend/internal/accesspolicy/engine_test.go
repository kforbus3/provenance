package accesspolicy

import (
	"testing"
	"time"
)

func mon(hour, min int) time.Time { // a Monday at the given local time
	return time.Date(2026, 7, 20, hour, min, 0, 0, time.UTC) // 2026-07-20 is a Monday
}

func TestSuperAdminNeverDenied(t *testing.T) {
	rules := []Rule{{Name: "deny all", DenyMessage: "no"}}
	d := Evaluate(rules, Subject{IsSuperAdmin: true}, HostAttrs{Environment: "production"}, mon(3, 0))
	if d.Denied {
		t.Error("super admin must never be denied")
	}
}

func TestEnvironmentMatch(t *testing.T) {
	rules := []Rule{{Name: "no prod", Environments: []string{"production"}}}
	if d := Evaluate(rules, Subject{}, HostAttrs{Environment: "production"}, mon(12, 0)); !d.Denied {
		t.Error("expected deny for production host")
	}
	if d := Evaluate(rules, Subject{}, HostAttrs{Environment: "staging"}, mon(12, 0)); d.Denied {
		t.Error("staging host should not match a production rule")
	}
}

func TestTagMatchAny(t *testing.T) {
	rules := []Rule{{Name: "pci", Tags: []string{"pci", "hipaa"}}}
	if d := Evaluate(rules, Subject{}, HostAttrs{Tags: []string{"web", "pci"}}, mon(12, 0)); !d.Denied {
		t.Error("host with a pci tag should match")
	}
	if d := Evaluate(rules, Subject{}, HostAttrs{Tags: []string{"web"}}, mon(12, 0)); d.Denied {
		t.Error("host without matching tag should not match")
	}
}

func TestProtocolMatch(t *testing.T) {
	rules := []Rule{{Name: "no rdp", Protocols: []string{"rdp"}}}
	if d := Evaluate(rules, Subject{}, HostAttrs{Protocol: "rdp"}, mon(12, 0)); !d.Denied {
		t.Error("rdp should match")
	}
	if d := Evaluate(rules, Subject{}, HostAttrs{Protocol: "ssh"}, mon(12, 0)); d.Denied {
		t.Error("ssh should not match an rdp rule")
	}
}

func TestExemptRoles(t *testing.T) {
	rules := []Rule{{Name: "no prod", Environments: []string{"production"}, ExemptRoles: []string{"SRE"}}}
	if d := Evaluate(rules, Subject{Roles: []string{"Developer"}}, HostAttrs{Environment: "production"}, mon(12, 0)); !d.Denied {
		t.Error("non-exempt user should be denied")
	}
	if d := Evaluate(rules, Subject{Roles: []string{"Developer", "SRE"}}, HostAttrs{Environment: "production"}, mon(12, 0)); d.Denied {
		t.Error("SRE should be exempt")
	}
}

func TestTimeWindowNormal(t *testing.T) {
	// Active 09:00–17:00 (a "deny during business hours" example is unusual, but this
	// tests the window math): deny only when inside 9-17.
	rules := []Rule{{Name: "window", ActiveStart: 9 * 60, ActiveEnd: 17 * 60}}
	if d := Evaluate(rules, Subject{}, HostAttrs{}, mon(12, 0)); !d.Denied {
		t.Error("noon should be inside 9-17 window")
	}
	if d := Evaluate(rules, Subject{}, HostAttrs{}, mon(8, 0)); d.Denied {
		t.Error("08:00 should be outside 9-17 window")
	}
	if d := Evaluate(rules, Subject{}, HostAttrs{}, mon(17, 0)); d.Denied {
		t.Error("17:00 is the exclusive end, outside window")
	}
}

func TestTimeWindowWrapsMidnight(t *testing.T) {
	// "Outside business hours" = deny 18:00–09:00 (wraps midnight).
	rules := []Rule{{Name: "after hours", ActiveStart: 18 * 60, ActiveEnd: 9 * 60}}
	for _, tc := range []struct {
		h, m int
		deny bool
	}{{20, 0, true}, {2, 0, true}, {8, 59, true}, {9, 0, false}, {12, 0, false}, {17, 59, false}, {18, 0, true}} {
		if d := Evaluate(rules, Subject{}, HostAttrs{}, mon(tc.h, tc.m)); d.Denied != tc.deny {
			t.Errorf("at %02d:%02d expected deny=%v, got %v", tc.h, tc.m, tc.deny, d.Denied)
		}
	}
}

func TestActiveDays(t *testing.T) {
	// Weekend-only rule (Sat=6, Sun=0). Monday should not match.
	rules := []Rule{{Name: "weekends", ActiveDays: []int{0, 6}}}
	if d := Evaluate(rules, Subject{}, HostAttrs{}, mon(12, 0)); d.Denied {
		t.Error("Monday should not match a weekend rule")
	}
	sat := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC) // Saturday
	if d := Evaluate(rules, Subject{}, HostAttrs{}, sat); !d.Denied {
		t.Error("Saturday should match a weekend rule")
	}
}

func TestNoRestrictionWhenStartEqualsEnd(t *testing.T) {
	rules := []Rule{{Name: "always", ActiveStart: 0, ActiveEnd: 0, Environments: []string{"production"}}}
	if d := Evaluate(rules, Subject{}, HostAttrs{Environment: "production"}, mon(3, 33)); !d.Denied {
		t.Error("equal start/end means no time restriction (always active)")
	}
}

func TestFirstMatchWinsAndReason(t *testing.T) {
	rules := []Rule{
		{ID: "a", Name: "first", Environments: []string{"production"}, DenyMessage: "blocked by first"},
		{ID: "b", Name: "second", Environments: []string{"production"}, DenyMessage: "blocked by second"},
	}
	d := Evaluate(rules, Subject{}, HostAttrs{Environment: "production"}, mon(12, 0))
	if !d.Denied || d.RuleID != "a" || d.Reason != "blocked by first" {
		t.Errorf("expected first rule to win, got %+v", d)
	}
}

func TestDefaultAllow(t *testing.T) {
	rules := []Rule{{Name: "no prod", Environments: []string{"production"}}}
	if d := Evaluate(rules, Subject{}, HostAttrs{Environment: "dev"}, mon(12, 0)); d.Denied {
		t.Error("no matching rule should allow")
	}
	if d := Evaluate(nil, Subject{}, HostAttrs{Environment: "production"}, mon(12, 0)); d.Denied {
		t.Error("empty policy set should allow")
	}
}
