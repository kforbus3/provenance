package assistant

import (
	"encoding/json"
	"testing"
)

func TestFastPathTool(t *testing.T) {
	cases := []struct {
		q        string
		wantName string // "" = no fast path
		wantArgs map[string]string
	}{
		// who ran <command> -> search_commands
		{"who ran df?", "search_commands", map[string]string{"query": "df"}},
		{"who ran the df command?", "search_commands", map[string]string{"query": "df"}},
		{"Who typed rm -rf /tmp", "search_commands", map[string]string{"query": "rm -rf /tmp"}},
		{"did anyone run systemctl restart nginx on web-01?", "search_commands", map[string]string{"query": "systemctl restart nginx", "hostname": "web-01"}},
		{"who executed `reboot` on nas", "search_commands", map[string]string{"query": "reboot", "hostname": "nas"}},

		// pending updates -> host_updates
		{"are there pending updates?", "host_updates", map[string]string{}},
		{"what are the pending updates?", "host_updates", map[string]string{}},
		{"which packages need updating on hypervisor?", "host_updates", map[string]string{"hostname": "hypervisor"}},
		{"what security updates are pending?", "host_updates", map[string]string{}},

		// downtime / offline-history -> host_availability
		{"did any host go offline today?", "host_availability", map[string]string{}},
		{"were there any outages this week?", "host_availability", map[string]string{}},
		{"was anything down overnight?", "host_availability", map[string]string{}},
		{"has any host gone offline recently?", "host_availability", map[string]string{}},

		// capacity / runway -> capacity_outlook
		{"are any hosts going to run out of disk space or memory in the next week?", "capacity_outlook", map[string]string{}},
		{"are any hosts going to run out of disk space soon?", "capacity_outlook", map[string]string{}},
		{"is anything about to run out of memory?", "capacity_outlook", map[string]string{}},
		{"which hosts are low on disk space?", "capacity_outlook", map[string]string{}},

		// failed logins / brute force -> security_events
		{"have there been any failed logins?", "security_events", map[string]string{}},
		{"is anyone brute-forcing the login?", "security_events", map[string]string{}},
		{"any account lockouts today?", "security_events", map[string]string{}},

		// CVE / vulnerability -> vulnerabilities
		{"what critical vulnerabilities are on debian?", "vulnerabilities", map[string]string{"hostname": "debian", "minSeverity": "critical"}},
		{"which hosts have CVEs?", "vulnerabilities", map[string]string{}},

		// accounts / MFA -> list_users
		{"who are the administrators?", "list_users", map[string]string{}},
		{"which accounts lack MFA?", "list_users", map[string]string{}},
		{"which accounts haven't logged in recently?", "list_users", map[string]string{}},

		// OS inventory -> query_hosts
		{"which OS versions are deployed across the fleet?", "query_hosts", map[string]string{}},
		{"what kernel versions are running?", "query_hosts", map[string]string{}},

		// aggregate / superlative -> query_hosts
		{"which host has the highest CPU load?", "query_hosts", map[string]string{}},
		{"which host has been up the longest?", "query_hosts", map[string]string{}},
		{"how many hosts are online?", "query_hosts", map[string]string{}},
		{"which hosts have high memory usage?", "query_hosts", map[string]string{}},

		// disk-provenance follow-up -> host_detail
		{"on nas, which filesystem does the disk-free percentage refer to?", "host_detail", map[string]string{"hostname": "nas"}},

		// schedules -> list_schedules
		{"what runs on a schedule, and when does it fire next?", "list_schedules", map[string]string{}},
		{"what is scheduled to run automatically?", "list_schedules", map[string]string{}},
		{"when is the next scheduled scan?", "list_schedules", map[string]string{}},
		// but scheduled-run FAILURE/history stays with the model
		{"did any scheduled scan fail last night?", "", nil},
		{"when did the nightly playbook last run?", "", nil},

		// action-y scan request must NOT hit the vulnerabilities READ fast-path
		{"run a vulnerability scan on web-01", "", nil},
		// session-style "who logged into X" must NOT hit list_users
		{"who logged into nas today?", "", nil},

		// must NOT fast-path (defer to the model)
		{"who logged into web-01 yesterday?", "", nil},
		{"who has access to db-02?", "", nil},
		{"how do I update Fleet?", "", nil},
		{"anything wrong with the fleet?", "", nil},
		{"what is the disk usage on web-01?", "", nil},
		{"which hosts are offline?", "", nil}, // current state, not history -> model
		{"are any hosts offline right now?", "", nil},
	}
	for _, c := range cases {
		name, args, ok := fastPathTool(c.q)
		if c.wantName == "" {
			if ok {
				t.Errorf("%q: expected no fast path, got %q %s", c.q, name, string(args))
			}
			continue
		}
		if !ok || name != c.wantName {
			t.Errorf("%q: got (%q, ok=%v), want %q", c.q, name, ok, c.wantName)
			continue
		}
		var got map[string]any
		_ = json.Unmarshal(args, &got)
		for k, want := range c.wantArgs {
			if gv, _ := got[k].(string); gv != want {
				t.Errorf("%q: arg %q = %q, want %q (args=%s)", c.q, k, gv, want, string(args))
			}
		}
	}
}
