package assistant

import (
	"sort"
	"strings"
)

// capabilityCatalog names, in operator language, every subject area the read-only
// tools cover, keyed by the tool that covers it.
//
// It exists because the assistant's most damaging failure mode is not a wrong answer
// but a confidently WRONG "I do not have a tool for that" — the user is told Fleet
// cannot see something it has been recording all along, and stops asking. That
// sentence is only safe if it is generated from the tool set rather than written by
// hand (the previous hardcoded list had already drifted: it omitted compliance scans,
// which is exactly what got denied) or invented by the model.
//
// TestCapabilityCatalogCoversEveryTool keeps this honest: adding a tool without
// adding its subject here fails the build's test run.
var capabilityCatalog = map[string]string{
	"query_hosts":           "host status, OS and kernel, hardware specs, uptime, disk and memory usage, and pending updates",
	"host_detail":           "per-host filesystems and network interfaces",
	"host_updates":          "the pending update packages on each host",
	"host_metric_history":   "disk, memory and load history over time",
	"host_availability":     "host up/down history and outage durations",
	"list_sessions":         "SSH sessions active right now",
	"session_history":       "past SSH sessions and how they ended",
	"search_commands":       "commands typed inside recorded terminal sessions",
	"recent_commands":       "ad-hoc commands run through Fleet",
	"recent_file_transfers": "SFTP file transfers",
	"compliance_scans":      "OpenSCAP compliance/benchmark scan results per host (CIS/STIG scores, pass/fail counts)",
	"scan_findings":         "the individual benchmark rules a host is failing",
	"recent_scans":          "the scan run log",
	"vulnerabilities":       "CVE/vulnerability scan findings",
	"windows_software":      "installed software on Windows hosts",
	"recent_playbook_runs":  "Ansible playbook runs",
	"list_schedules":        "what runs automatically and when it fires next",
	"audit_log":             "the audit trail of changes",
	"security_events":       "failed logins, lockouts, MFA failures, and behavioural anomalies",
	"list_users":            "user accounts, roles, and MFA enrolment",
	"list_approvals":        "pending access approvals and active temporary grants",
	"access_control":        "groups, roles and their permissions, service accounts and API tokens, and access reviews",
	"expiring_credentials":  "credentials, certificates and keys that are expiring or overdue for rotation",
	"fleet_insights":        "what currently needs attention across the fleet",
	"platform_status":       "Fleet's own cluster, enrollment jobs, federation sites and database replication",
	"search_docs":           "the Moorgate product documentation",
}

// capabilityStatement renders the catalogue as one sentence, for the answer given
// when nothing matched. Sorted so the sentence is stable between runs.
func capabilityStatement() string {
	seen := map[string]bool{}
	subjects := make([]string, 0, len(capabilityCatalog))
	for _, subject := range capabilityCatalog {
		if seen[subject] {
			continue
		}
		seen[subject] = true
		subjects = append(subjects, subject)
	}
	sort.Strings(subjects)
	return "Fleet does hold: " + strings.Join(subjects, "; ") +
		". If your question is about one of those, ask again naming it and I will look it up."
}
