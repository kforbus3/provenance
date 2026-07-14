// Package assistant implements a read-only, RBAC-scoped natural-language query
// layer over fleet data, backed by a local Ollama instance. The model only ever
// calls a curated query tool (it cannot run SQL or act on hosts); every answer
// is grounded in the real rows returned by that tool.
package assistant

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

const (
	maxToolIterations = 4
	askTimeout        = 5 * time.Minute
)

// Service orchestrates assistant conversations.
type Service struct {
	store           *store.Store
	log             *slog.Logger
	metricRetention time.Duration // caps the host_metric_history window (0 = history disabled)
	asks            sync.Map      // id -> *AskResult (pointer replaced atomically on completion)
}

func New(st *store.Store, log *slog.Logger, metricRetention time.Duration) *Service {
	return &Service{store: st, log: log, metricRetention: metricRetention}
}

// Settings is the persisted assistant configuration.
type Settings struct {
	Enabled   bool   `json:"enabled"`
	OllamaURL string `json:"ollamaUrl"`
	Model     string `json:"model"`
}

func (s *Service) settings(ctx context.Context) Settings {
	var a Settings
	if raw, err := s.store.GetSetting(ctx, "assistant"); err == nil {
		_ = json.Unmarshal(raw, &a)
	}
	return a
}

// Status reports whether the assistant is enabled, the model, and reachability.
func (s *Service) Status(ctx context.Context) map[string]any {
	cfg := s.settings(ctx)
	reachable := false
	if cfg.OllamaURL != "" {
		cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		if _, err := newOllama(cfg.OllamaURL).listModels(cctx); err == nil {
			reachable = true
		}
	}
	return map[string]any{
		"enabled":   cfg.Enabled,
		"model":     cfg.Model,
		"reachable": reachable,
		"ready":     cfg.Enabled && cfg.Model != "" && reachable,
	}
}

// Models lists models from the configured (or overridden) Ollama URL.
func (s *Service) Models(ctx context.Context, urlOverride string) ([]string, error) {
	url := urlOverride
	if url == "" {
		url = s.settings(ctx).OllamaURL
	}
	if url == "" {
		return []string{}, nil
	}
	return newOllama(url).listModels(ctx)
}

// SessionRow is one active SSH session for the list_sessions panel.
type SessionRow struct {
	Username  string `json:"username"`
	Hostname  string `json:"hostname"`
	ClientIP  string `json:"clientIp,omitempty"`
	StartedAt string `json:"startedAt"`
}

// MetricHistory is a host's bucketed metric time series, returned to the UI so it
// can render a trend chart beneath the answer.
type MetricHistory struct {
	Hostname      string                     `json:"hostname"`
	WindowHours   int                        `json:"windowHours"`
	BucketMinutes int                        `json:"bucketMinutes"`
	Points        []store.MetricHistoryPoint `json:"points"`
}

// AskResult is the (eventual) outcome of a question, with structured data the UI
// renders beneath the answer (whichever tool the model used).
type AskResult struct {
	Status   string                    `json:"status"` // pending|done|error
	Answer   string                    `json:"answer,omitempty"`
	Hosts    []models.AssistantHostRow `json:"hosts,omitempty"`
	Sessions []SessionRow              `json:"sessions,omitempty"`
	Host     *models.Host              `json:"host,omitempty"`
	History  *MetricHistory            `json:"history,omitempty"`
	Error    string                    `json:"error,omitempty"`
	created  time.Time
	owner    uuid.UUID // the user who asked; only they may read the result
}

// answerData bundles structured tool output collected during a conversation.
type answerData struct {
	hosts    []models.AssistantHostRow
	sessions []SessionRow
	host     *models.Host
	history  *MetricHistory
}

// Caller identity captured for RBAC-scoped tool execution in the background.
type Caller struct {
	UserID          uuid.UUID
	IsSuperAdmin    bool
	Username        string
	CanViewSessions bool // Session.Replay — gates the list_sessions tool
	CanViewScans    bool // Host.Scan — gates the recent_scans tool
	CanViewRuns     bool // Playbook.Run — gates the recent_playbook_runs tool
}

// Ask starts answering a question in the background and returns a poll id. Async
// because local LLM inference can exceed the HTTP request timeout.
func (s *Service) Ask(ctx context.Context, question string, who Caller) (string, bool) {
	cfg := s.settings(ctx)
	if !cfg.Enabled || cfg.OllamaURL == "" || cfg.Model == "" {
		return "", false
	}
	id := uuid.NewString()
	s.asks.Store(id, &AskResult{Status: "pending", created: time.Now(), owner: who.UserID})
	go s.run(id, question, who, cfg)
	return id, true
}

// Result returns and (when finished) removes a pending result, but only for the
// user who created it (results can carry host/session data scoped to that caller).
func (s *Service) Result(id string, caller uuid.UUID) (*AskResult, bool) {
	v, ok := s.asks.Load(id)
	if !ok {
		return nil, false
	}
	r := v.(*AskResult)
	if r.owner != caller {
		return nil, false
	}
	if r.Status != "pending" {
		s.asks.Delete(id)
	}
	return r, true
}

func (s *Service) run(id, question string, who Caller, cfg Settings) {
	ctx, cancel := context.WithTimeout(context.Background(), askTimeout)
	defer cancel()
	s.cleanup()

	answer, data, err := s.converse(ctx, cfg, question, who)
	if err != nil {
		s.log.Warn("assistant ask failed", "user", who.Username, "err", err)
		s.asks.Store(id, &AskResult{Status: "error", Error: friendlyErr(err), created: time.Now(), owner: who.UserID})
		return
	}
	s.asks.Store(id, &AskResult{
		Status: "done", Answer: answer,
		Hosts: data.hosts, Sessions: data.sessions, Host: data.host, History: data.history,
		created: time.Now(), owner: who.UserID,
	})
}

// converse runs the tool-calling loop: the model picks query_hosts + filters, we
// run the RBAC-scoped query, feed results back, and the model narrates.
func (s *Service) converse(ctx context.Context, cfg Settings, question string, who Caller) (string, answerData, error) {
	client := newOllama(cfg.OllamaURL)
	messages := []chatMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: question},
	}
	var data answerData

	for i := 0; i < maxToolIterations; i++ {
		resp, err := client.chat(ctx, chatRequest{Model: cfg.Model, Messages: messages, Tools: tools})
		if err != nil {
			return "", data, err
		}
		msg := resp.Message
		if len(msg.ToolCalls) == 0 {
			return strings.TrimSpace(msg.Content), data, nil
		}
		messages = append(messages, msg)
		for _, tc := range msg.ToolCalls {
			var result any
			switch tc.Function.Name {
			case "query_hosts":
				rows := s.runQueryHosts(ctx, tc.Function.Arguments, who)
				data.hosts = rows
				result = map[string]any{"count": len(rows), "hosts": rows}
			case "list_sessions":
				sessions, payload := s.listSessions(ctx, who)
				if sessions != nil {
					data.sessions = sessions
				}
				result = payload
			case "host_detail":
				host, payload := s.hostDetail(ctx, tc.Function.Arguments, who)
				if host != nil {
					data.host = host
				}
				result = payload
			case "recent_scans":
				result = s.runRecentScans(ctx, tc.Function.Arguments, who)
			case "recent_playbook_runs":
				result = s.runRecentPlaybookRuns(ctx, who)
			case "host_metric_history":
				hist, payload := s.runMetricHistory(ctx, tc.Function.Arguments, who)
				if hist != nil {
					data.history = hist
				}
				result = payload
			default:
				result = map[string]any{"error": "unknown tool"}
			}
			payload, _ := json.Marshal(result)
			messages = append(messages, chatMessage{Role: "tool", Content: string(payload)})
		}
	}
	// Ran out of iterations; summarize from what we have.
	return "I couldn't fully resolve that. Here is the data I found.", data, nil
}

func (s *Service) runQueryHosts(ctx context.Context, raw json.RawMessage, who Caller) []models.AssistantHostRow {
	var a queryHostsArgs
	_ = json.Unmarshal(raw, &a)
	rows, err := s.store.QueryHostsForAssistant(ctx, a.toQuery(who))
	if err != nil {
		s.log.Warn("assistant query_hosts", "err", err)
		return nil
	}
	return rows
}

// listSessions returns the structured sessions (nil on error/denied) plus the
// payload to feed the model.
func (s *Service) listSessions(ctx context.Context, who Caller) ([]SessionRow, any) {
	if !who.CanViewSessions && !who.IsSuperAdmin {
		return nil, map[string]any{"error": "you do not have permission to view sessions"}
	}
	rows, err := s.store.ActiveSSHSessions(ctx, 200)
	if err != nil {
		s.log.Warn("assistant list_sessions", "err", err)
		return nil, map[string]any{"error": "could not list sessions"}
	}
	out := make([]SessionRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, SessionRow{
			Username: r.Username, Hostname: r.Hostname, ClientIP: r.ClientIP,
			StartedAt: r.StartedAt.Format(time.RFC3339),
		})
	}
	return out, map[string]any{"count": len(out), "sessions": out}
}

// hostDetail returns the full host (nil on error/denied) plus the model payload.
func (s *Service) hostDetail(ctx context.Context, raw json.RawMessage, who Caller) (*models.Host, any) {
	var a hostDetailArgs
	_ = json.Unmarshal(raw, &a)
	if a.Hostname == "" {
		return nil, map[string]any{"error": "hostname is required"}
	}
	host, err := s.store.HostByHostname(ctx, a.Hostname)
	if err != nil {
		return nil, map[string]any{"error": "no host named " + a.Hostname}
	}
	if !who.IsSuperAdmin {
		ok, err := s.store.UserCanAccessHost(ctx, who.UserID, host.ID)
		if err != nil || !ok {
			return nil, map[string]any{"error": "you do not have access to that host"}
		}
	}
	return host, host
}

// runRecentScans returns recent security scans (scoped to the caller's hosts).
func (s *Service) runRecentScans(ctx context.Context, raw json.RawMessage, who Caller) any {
	if !who.CanViewScans && !who.IsSuperAdmin {
		return map[string]any{"error": "you do not have permission to view scans"}
	}
	var a recentScansArgs
	_ = json.Unmarshal(raw, &a)
	rows, err := s.store.RecentScansForAssistant(ctx, who.UserID, who.IsSuperAdmin, a.Hostname, a.Limit)
	if err != nil {
		s.log.Warn("assistant recent_scans", "err", err)
		return map[string]any{"error": "could not list scans"}
	}
	return map[string]any{"count": len(rows), "scans": rows}
}

// runRecentPlaybookRuns returns recent playbook runs (gated by Playbook.Run).
func (s *Service) runRecentPlaybookRuns(ctx context.Context, who Caller) any {
	if !who.CanViewRuns && !who.IsSuperAdmin {
		return map[string]any{"error": "you do not have permission to view playbook runs"}
	}
	rows, err := s.store.RecentPlaybookRunsForAssistant(ctx, 50)
	if err != nil {
		s.log.Warn("assistant recent_playbook_runs", "err", err)
		return map[string]any{"error": "could not list playbook runs"}
	}
	return map[string]any{"count": len(rows), "runs": rows}
}

// runMetricHistory returns a host's bucketed metric history for trend questions,
// scoped to hosts the caller can access and clamped to the server's retention. It
// returns the structured series for the UI chart (nil when empty/denied) plus the
// payload fed to the model.
func (s *Service) runMetricHistory(ctx context.Context, raw json.RawMessage, who Caller) (*MetricHistory, any) {
	if s.metricRetention <= 0 {
		return nil, map[string]any{"error": "metric history is not enabled on this server"}
	}
	var a metricHistoryArgs
	_ = json.Unmarshal(raw, &a)
	if a.Hostname == "" {
		return nil, map[string]any{"error": "hostname is required"}
	}
	host, err := s.store.HostByHostname(ctx, a.Hostname)
	if err != nil {
		return nil, map[string]any{"error": "no host named " + a.Hostname}
	}
	if !who.IsSuperAdmin {
		ok, aerr := s.store.UserCanAccessHost(ctx, who.UserID, host.ID)
		if aerr != nil || !ok {
			return nil, map[string]any{"error": "you do not have access to that host"}
		}
	}
	// Window: default 48h; clamp to [1h, retention] so we never claim data we pruned.
	window := time.Duration(a.Hours) * time.Hour
	if a.Hours <= 0 {
		window = 48 * time.Hour
	}
	if window > s.metricRetention {
		window = s.metricRetention
	}
	if window < time.Hour {
		window = time.Hour
	}
	// Aim for <= ~72 buckets so the series stays compact enough to feed the model.
	const targetBuckets = 72
	bucket := window / targetBuckets
	if bucket < time.Minute {
		bucket = time.Minute
	}
	points, err := s.store.MetricHistory(ctx, host.ID, time.Now().Add(-window), bucket)
	if err != nil {
		s.log.Warn("assistant metric history", "err", err)
		return nil, map[string]any{"error": "could not load metric history"}
	}
	hist := &MetricHistory{
		Hostname:      host.Hostname,
		WindowHours:   int(window / time.Hour),
		BucketMinutes: int(bucket / time.Minute),
		Points:        points,
	}
	payload := map[string]any{
		"hostname":      hist.Hostname,
		"windowHours":   hist.WindowHours,
		"bucketMinutes": hist.BucketMinutes,
		"count":         len(points),
		"points":        points,
	}
	if len(points) == 0 {
		payload["note"] = "no metric history recorded for this host in the requested window (it may have been enrolled recently, or history collection just started)"
		return nil, payload // nothing to chart
	}
	return hist, payload
}

// cleanup drops results older than the ask timeout to bound memory.
func (s *Service) cleanup() {
	cutoff := time.Now().Add(-askTimeout)
	s.asks.Range(func(k, v any) bool {
		if r, ok := v.(*AskResult); ok && r.created.Before(cutoff) {
			s.asks.Delete(k)
		}
		return true
	})
}

func friendlyErr(err error) string {
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return "The assistant could not reach the model or it failed: " + msg
}
