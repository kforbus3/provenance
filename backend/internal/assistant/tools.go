package assistant

import "github.com/fleet-terminal/backend/internal/store"

const systemPrompt = `You are Fleet Assistant, a read-only helper for a fleet of Linux hosts.

Answer questions about the fleet ONLY by calling the query_hosts tool — never invent
host names, counts, or metrics. query_hosts returns each host's kernel version, OS
name + version, architecture, CPU count, total memory, uptime, primary IP, status,
disk/memory/load metrics, and pending package-update counts (updatesAvailable +
securityUpdates), so use it for ALL host questions (specs, inventory, and available
updates too, not just metrics). Translate the request into filter fields, for example:
- "hosts with less than 20% disk free" -> diskFreePctMax: 20
- "offline debian boxes" -> status: "offline", osContains: "debian"
- "prod hosts under heavy load" -> environment: "production", loadPerCoreMin: 1
- "which hosts have updates available" -> updatesAvailableMin: 1, then read updatesAvailable
- "hosts with security updates" -> securityUpdatesMin: 1, then read securityUpdates
- "list the kernel versions of all hosts" -> call query_hosts with no filters, then
  read the kernel field from each returned host

You also have:
- list_sessions: who is currently connected to which host (active SSH sessions).
- host_detail: full detail for ONE host by exact hostname, including every mounted
  filesystem's usage and all network interfaces. Use it for questions like "which
  filesystem is full on web-01" or "what subnet is db-02 on".
- recent_scans: recent OpenSCAP security scans (scheduled or manual), most recent
  first, with host, profile, status, score, and when they ran. Use for "when was
  the last security scan on web-01" or "which hosts were scanned recently".
- recent_playbook_runs: recent Ansible playbook runs (scheduled or manual), with
  playbook name, target, status, and when they ran. Use for "when did the
  apt-upgrade playbook last run" or "what playbooks ran recently". When the user
  asks about the LAST scan or playbook run, read the most recent matching entry
  and report its time.

All percentages are 0-100. After a tool returns, give a brief, factual answer that
references the data the user will see. If the question is not about the fleet, say you
can only answer questions about the fleet. Results are already limited to what the user
is allowed to see.`

// tools is the curated, read-only tool surface exposed to the model.
var tools = []toolDef{{
	Type: "function",
	Function: toolFunction{
		Name:        "query_hosts",
		Description: "Find managed hosts matching structured filters. Returns, per host: hostname, environment, status, primary IP, OS name + version, kernel version, architecture, CPU count, total memory (MB), SSH version, uptime, disk-free %, memory-used %, load per core, latency, WireGuard tunnel health, last-seen time, number of pending package updates (updatesAvailable) and pending security updates (securityUpdates), groups, tags, owner, and enrolled state. Use it for ANY question about hosts (kernel/OS/specs/uptime/groups/tags/owner/VPN health/available updates included). All filters are optional and combined with AND; call with no filters to list all hosts.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"status":              map[string]any{"type": "string", "enum": []string{"online", "offline", "unknown"}, "description": "host reachability"},
				"environment":         map[string]any{"type": "string", "description": "exact environment label, e.g. production"},
				"osContains":          map[string]any{"type": "string", "description": "substring match on OS name, e.g. debian"},
				"hostnameContains":    map[string]any{"type": "string", "description": "substring match on hostname"},
				"group":               map[string]any{"type": "string", "description": "exact group name the host belongs to"},
				"tag":                 map[string]any{"type": "string", "description": "exact tag on the host"},
				"diskFreePctMax":      map[string]any{"type": "number", "description": "max free disk % on the tightest filesystem (e.g. 20 = less than 20% free)"},
				"diskFreePctMin":      map[string]any{"type": "number", "description": "min free disk %"},
				"memUsedPctMin":       map[string]any{"type": "number", "description": "min memory used %"},
				"loadPerCoreMin":      map[string]any{"type": "number", "description": "min load average per CPU core"},
				"updatesAvailableMin": map[string]any{"type": "integer", "description": "min number of pending package updates (e.g. 1 = hosts that have any updates available)"},
				"securityUpdatesMin":  map[string]any{"type": "integer", "description": "min number of pending SECURITY updates (e.g. 1 = hosts with security updates available)"},
				"enrolled":            map[string]any{"type": "boolean", "description": "filter by enrolled state"},
				"wireguardDown":       map[string]any{"type": "boolean", "description": "true = only hosts whose WireGuard tunnel is down"},
				"limit":               map[string]any{"type": "integer", "description": "max rows (default/cap 200)"},
			},
		},
	},
}, {
	Type: "function",
	Function: toolFunction{
		Name:        "list_sessions",
		Description: "List the SSH sessions currently active across the fleet (who is connected to which host right now), with username, hostname, client IP, and start time. Takes no arguments.",
		Parameters:  map[string]any{"type": "object", "properties": map[string]any{}},
	},
}, {
	Type: "function",
	Function: toolFunction{
		Name:        "host_detail",
		Description: "Get full detail for a single host by its exact hostname: complete inventory, status, every mounted filesystem's usage, and all network interfaces with their addresses. Use after query_hosts when the user asks about a specific host's filesystems or network.",
		Parameters: map[string]any{
			"type":       "object",
			"properties": map[string]any{"hostname": map[string]any{"type": "string", "description": "exact hostname"}},
			"required":   []string{"hostname"},
		},
	},
}, {
	Type: "function",
	Function: toolFunction{
		Name:        "recent_scans",
		Description: "List recent OpenSCAP security scans, most recent first. Each entry has hostname, profile, status (completed/failed), score, pass/fail counts, who/what requested it, a `scheduled` boolean (true = run automatically by a schedule, false = run manually), and when it ran (createdAt/finishedAt). Use for questions like 'when was the last security scan on web-01' or 'which hosts were scanned recently'; for 'scheduled scans' specifically, keep entries where scheduled is true. Optionally filter by hostname.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"hostname": map[string]any{"type": "string", "description": "exact hostname to filter to (optional)"},
				"limit":    map[string]any{"type": "integer", "description": "max rows (default 50)"},
			},
		},
	},
}, {
	Type: "function",
	Function: toolFunction{
		Name:        "recent_playbook_runs",
		Description: "List recent Ansible playbook runs, most recent first. Each entry has the playbook name, target (a host or a group + host count), whether it was a dry run, a `scheduled` boolean (true = run automatically by a schedule, false = run manually), status (completed/failed), who/what requested it, and when it ran. Use for questions like 'when did the apt-upgrade playbook last run' or 'what playbooks ran against my hosts recently'; for 'scheduled' runs specifically, keep entries where scheduled is true.",
		Parameters: map[string]any{
			"type":       "object",
			"properties": map[string]any{"limit": map[string]any{"type": "integer", "description": "max rows (default 50)"}},
		},
	},
}}

type recentScansArgs struct {
	Hostname string `json:"hostname"`
	Limit    int    `json:"limit"`
}

type recentRunsArgs struct {
	Limit int `json:"limit"`
}

type hostDetailArgs struct {
	Hostname string `json:"hostname"`
}

// queryHostsArgs mirrors the tool's parameter schema.
type queryHostsArgs struct {
	Status              string   `json:"status"`
	Environment         string   `json:"environment"`
	OSContains          string   `json:"osContains"`
	HostnameContains    string   `json:"hostnameContains"`
	Group               string   `json:"group"`
	Tag                 string   `json:"tag"`
	DiskFreePctMax      *float64 `json:"diskFreePctMax"`
	DiskFreePctMin      *float64 `json:"diskFreePctMin"`
	MemUsedPctMin       *float64 `json:"memUsedPctMin"`
	LoadPerCoreMin      *float64 `json:"loadPerCoreMin"`
	UpdatesAvailableMin *int     `json:"updatesAvailableMin"`
	SecurityUpdatesMin  *int     `json:"securityUpdatesMin"`
	Enrolled            *bool    `json:"enrolled"`
	WireguardDown       *bool    `json:"wireguardDown"`
	Limit               int      `json:"limit"`
}

func (a queryHostsArgs) toQuery(who Caller) store.HostQuery {
	return store.HostQuery{
		Status:              a.Status,
		Environment:         a.Environment,
		OSContains:          a.OSContains,
		HostnameContains:    a.HostnameContains,
		Group:               a.Group,
		Tag:                 a.Tag,
		DiskFreePctMax:      a.DiskFreePctMax,
		DiskFreePctMin:      a.DiskFreePctMin,
		MemUsedPctMin:       a.MemUsedPctMin,
		LoadPerCoreMin:      a.LoadPerCoreMin,
		UpdatesAvailableMin: a.UpdatesAvailableMin,
		SecurityUpdatesMin:  a.SecurityUpdatesMin,
		Enrolled:            a.Enrolled,
		WGDown:              a.WireguardDown,
		Limit:               a.Limit,
		UserID:              who.UserID,
		IsSuperAdmin:        who.IsSuperAdmin,
	}
}
