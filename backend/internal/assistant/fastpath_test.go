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
