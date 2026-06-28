package assistant

import "github.com/fleet-terminal/backend/internal/store"

const systemPrompt = `You are Fleet Assistant, a read-only helper for a fleet of Linux hosts.

Answer questions about the fleet ONLY by calling the query_hosts tool — never invent
host names, counts, or metrics. Translate the user's request into the tool's filter
fields, for example:
- "hosts with less than 20% disk free" -> diskFreePctMax: 20
- "offline debian boxes" -> status: "offline", osContains: "debian"
- "prod hosts under heavy load" -> environment: "production", loadPerCoreMin: 1

All percentages are 0-100. After the tool returns, give a brief, factual answer that
references the host list the user will see. If the question is not about the fleet's
hosts, say you can only answer questions about fleet hosts. Results are already limited
to hosts the user is allowed to see.`

// tools is the curated, read-only tool surface exposed to the model.
var tools = []toolDef{{
	Type: "function",
	Function: toolFunction{
		Name:        "query_hosts",
		Description: "Find managed hosts matching structured filters. Returns matching hosts with status, OS, primary IP, disk-free %, memory-used %, and load per core. All filters are optional and combined with AND.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"status":           map[string]any{"type": "string", "enum": []string{"online", "offline", "unknown"}, "description": "host reachability"},
				"environment":      map[string]any{"type": "string", "description": "exact environment label, e.g. production"},
				"osContains":       map[string]any{"type": "string", "description": "substring match on OS name, e.g. debian"},
				"hostnameContains": map[string]any{"type": "string", "description": "substring match on hostname"},
				"diskFreePctMax":   map[string]any{"type": "number", "description": "max free disk % on the tightest filesystem (e.g. 20 = less than 20% free)"},
				"diskFreePctMin":   map[string]any{"type": "number", "description": "min free disk %"},
				"memUsedPctMin":    map[string]any{"type": "number", "description": "min memory used %"},
				"loadPerCoreMin":   map[string]any{"type": "number", "description": "min load average per CPU core"},
				"limit":            map[string]any{"type": "integer", "description": "max rows (default/cap 200)"},
			},
		},
	},
}}

// queryHostsArgs mirrors the tool's parameter schema.
type queryHostsArgs struct {
	Status           string   `json:"status"`
	Environment      string   `json:"environment"`
	OSContains       string   `json:"osContains"`
	HostnameContains string   `json:"hostnameContains"`
	DiskFreePctMax   *float64 `json:"diskFreePctMax"`
	DiskFreePctMin   *float64 `json:"diskFreePctMin"`
	MemUsedPctMin    *float64 `json:"memUsedPctMin"`
	LoadPerCoreMin   *float64 `json:"loadPerCoreMin"`
	Limit            int      `json:"limit"`
}

func (a queryHostsArgs) toQuery(who Caller) store.HostQuery {
	return store.HostQuery{
		Status:           a.Status,
		Environment:      a.Environment,
		OSContains:       a.OSContains,
		HostnameContains: a.HostnameContains,
		DiskFreePctMax:   a.DiskFreePctMax,
		DiskFreePctMin:   a.DiskFreePctMin,
		MemUsedPctMin:    a.MemUsedPctMin,
		LoadPerCoreMin:   a.LoadPerCoreMin,
		Limit:            a.Limit,
		UserID:           who.UserID,
		IsSuperAdmin:     who.IsSuperAdmin,
	}
}
