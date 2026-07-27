package assistant

import "testing"

// TestFastPathDispatchCoverage guards against fast-path routing/handler drift: if
// fastPathTool routes a question to a tool, the converse() fast-path switch MUST have a
// dispatch case for it — otherwise the result is empty and the answer is a false
// "nothing found" (this bit us for session_history and audit_log). Keep `handled` in
// sync with the switch in converse().
func TestFastPathDispatchCoverage(t *testing.T) {
	probes := []string{
		"who ran df on web-01", "what updates are pending on nas", "did any host go offline today",
		"will any host run out of disk this week", "any failed logins this week",
		"any failed scans or playbook runs recently", "what changed in the audit log today",
		"what CVEs are on nas", "which accounts have no MFA", "which hosts have less than 80% disk free",
		"who last connected to nas", "what runs on a schedule", "disk usage trend on nas over the past week",
	}
	handled := map[string]bool{
		"host_updates": true, "search_commands": true, "host_availability": true,
		"capacity_outlook": true, "security_events": true, "vulnerabilities": true, "list_users": true,
		"query_hosts": true, "host_detail": true, "list_schedules": true, "fleet_insights": true,
		"session_history": true, "recent_activity_failures": true, "audit_log": true, "host_metric_history": true,
	}
	for _, q := range probes {
		if name, _, ok := fastPathTool(q); ok && !handled[name] {
			t.Errorf("%q routes to %q, which has no dispatch case in converse() (would return empty)", q, name)
		}
	}
}
