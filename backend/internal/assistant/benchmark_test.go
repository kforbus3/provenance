package assistant

// Model routing benchmark for the Ask assistant. Disabled by default; it makes
// live calls to a real Ollama instance. Run it explicitly against candidate models:
//
//	PROV_BENCH_URL=http://10.10.0.162:11434 \
//	PROV_BENCH_MODELS='gemma4:26b,gpt-oss:20b,qwen2.5:14b-instruct,qwen3:14b,mistral-small' \
//	go test ./internal/assistant/ -run TestModelRoutingBenchmark -v -timeout 2h
//
// It measures RAW tool-routing accuracy (fast-path disabled): for each labelled
// question it sends the exact production system prompt + read-only tool surface to
// the model and checks whether the model's first tool call matches an acceptable
// tool. This is the signal that decides how reliable Ask is without the fast-path
// crutch. Temperature is pinned to 0 for reproducibility.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// benchCase is a question and the set of tools that correctly answer it. Where a
// question is genuinely served by more than one tool, all acceptable tools are
// listed; a routing counts as correct if the model picks any of them.
type benchCase struct {
	q    string
	want []string
}

var benchCases = []benchCase{
	// health / insights
	{"any problems?", []string{"prov_insights"}},
	{"anything I should worry about this morning?", []string{"prov_insights"}},
	{"give me a fleet health summary", []string{"prov_insights"}},
	// updates
	{"what security updates are pending?", []string{"host_updates"}},
	{"which packages need updating on hypervisor?", []string{"host_updates"}},
	{"are there any pending updates?", []string{"host_updates"}},
	// availability / downtime history
	{"did any host go offline today?", []string{"host_availability"}},
	{"were there any outages this week?", []string{"host_availability"}},
	{"which hosts are offline right now?", []string{"query_hosts", "host_availability"}},
	// capacity / runway. NB: capacity_outlook is a fast-path-only route (not in the
	// model-facing `tools` surface), so the correct MODEL answer for these is
	// prov_insights, which carries the disk-runway projection. query_hosts is an
	// acceptable current-state fallback for the point-in-time "low on disk" phrasing.
	{"are any hosts about to run out of disk space?", []string{"prov_insights"}},
	{"which hosts are low on disk?", []string{"prov_insights", "query_hosts"}},
	// security events
	{"have there been any failed logins?", []string{"security_events"}},
	{"is anyone brute-forcing ssh?", []string{"security_events"}},
	// vulnerabilities
	{"which hosts have critical CVEs?", []string{"vulnerabilities"}},
	{"what vulnerabilities are on debian?", []string{"vulnerabilities"}},
	// users / accounts
	{"who are the administrators?", []string{"list_users"}},
	{"which accounts lack MFA?", []string{"list_users"}},
	// inventory / aggregate
	{"which OS versions are deployed across the fleet?", []string{"query_hosts"}},
	{"which host has the highest CPU load?", []string{"query_hosts"}},
	{"how many hosts are online?", []string{"query_hosts"}},
	// host detail
	{"what is the disk usage on web-01?", []string{"host_detail"}},
	{"show me details for nas", []string{"host_detail"}},
	// sessions / commands
	{"who ran df on nas?", []string{"search_commands"}},
	{"did anyone run reboot recently?", []string{"search_commands", "recent_commands"}},
	{"who logged into web-01 yesterday?", []string{"session_history", "list_sessions"}},
	{"who is connected right now?", []string{"list_sessions"}},
	// scans
	{"what were the results of the last scan on web-01?", []string{"recent_scans"}},
	{"show me recent compliance scans", []string{"recent_scans"}},
	// playbooks
	{"did the last playbook run succeed?", []string{"recent_playbook_runs"}},
	{"show recent ansible runs", []string{"recent_playbook_runs"}},
	// schedules
	{"what runs on a schedule?", []string{"list_schedules"}},
	{"when does the next scan fire?", []string{"list_schedules"}},
	// audit
	{"show me recent audit events", []string{"audit_log"}},
	{"what configuration changed in the last 24 hours?", []string{"audit_log"}},
	// file transfers
	{"were any files transferred recently?", []string{"recent_file_transfers"}},
	// metric history / trend
	{"show the disk space trend for nas this week", []string{"host_metric_history"}},
	{"what's the memory trend on hypervisor?", []string{"host_metric_history"}},
	// docs / how-to
	{"how do I enroll a new host?", []string{"search_docs"}},
	{"how do I update Provenance?", []string{"search_docs"}},
	// approvals
	{"are there any pending access requests?", []string{"list_approvals"}},
	// windows software
	{"what software is installed on the windows box?", []string{"windows_software"}},
	// platform
	{"is the fleet backend healthy?", []string{"platform_status", "prov_insights"}},
}

func TestModelRoutingBenchmark(t *testing.T) {
	url := os.Getenv("PROV_BENCH_URL")
	modelsEnv := os.Getenv("PROV_BENCH_MODELS")
	if url == "" || modelsEnv == "" {
		t.Skip("set PROV_BENCH_URL and PROV_BENCH_MODELS to run the routing benchmark")
	}
	var models []string
	for _, m := range strings.Split(modelsEnv, ",") {
		if m = strings.TrimSpace(m); m != "" {
			models = append(models, m)
		}
	}
	client := newOllama(url)

	type modelResult struct {
		model  string
		hits   int
		noTool int
		total  int
		avgMS  int64
		misses []string // "question -> picked"
	}
	var results []modelResult

	for _, model := range models {
		res := modelResult{model: model, total: len(benchCases)}
		var totalMS int64
		t.Logf("=== benchmarking %s ===", model)
		for _, c := range benchCases {
			msgs := []chatMessage{
				{Role: "system", Content: systemPrompt},
				{Role: "user", Content: c.q},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			start := time.Now()
			resp, err := client.chat(ctx, chatRequest{
				Model:    model,
				Messages: msgs,
				Tools:    tools, // read-only surface, exactly as production offers it
				Options:  map[string]any{"temperature": 0},
			})
			ms := time.Since(start).Milliseconds()
			cancel()
			totalMS += ms
			if err != nil {
				res.misses = append(res.misses, fmt.Sprintf("%q -> ERROR: %v", c.q, err))
				continue
			}
			picked := "(no tool / prose)"
			if len(resp.Message.ToolCalls) > 0 {
				picked = resp.Message.ToolCalls[0].Function.Name
			} else {
				res.noTool++
			}
			if acceptable(picked, c.want) {
				res.hits++
			} else {
				res.misses = append(res.misses, fmt.Sprintf("%q -> %s (want %s)", c.q, picked, strings.Join(c.want, "|")))
			}
		}
		if res.total > 0 {
			res.avgMS = totalMS / int64(res.total)
		}
		results = append(results, res)
	}

	// Rank by accuracy, then speed.
	sort.Slice(results, func(a, b int) bool {
		if results[a].hits != results[b].hits {
			return results[a].hits > results[b].hits
		}
		return results[a].avgMS < results[b].avgMS
	})

	t.Log("")
	t.Log("================ ROUTING ACCURACY (fast-path disabled) ================")
	for _, r := range results {
		pct := 0.0
		if r.total > 0 {
			pct = 100 * float64(r.hits) / float64(r.total)
		}
		t.Logf("%-24s  %2d/%2d correct (%.0f%%)   no-tool:%d   avg %dms/call",
			r.model, r.hits, r.total, pct, r.noTool, r.avgMS)
	}
	t.Log("")
	for _, r := range results {
		t.Logf("---- misses: %s ----", r.model)
		if len(r.misses) == 0 {
			t.Log("   (none)")
		}
		for _, m := range r.misses {
			t.Logf("   %s", m)
		}
	}
}

func acceptable(picked string, want []string) bool {
	for _, w := range want {
		if picked == w {
			return true
		}
	}
	return false
}
