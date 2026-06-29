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
	store *store.Store
	log   *slog.Logger
	asks  sync.Map // id -> *AskResult (pointer replaced atomically on completion)
}

func New(st *store.Store, log *slog.Logger) *Service {
	return &Service{store: st, log: log}
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

// AskResult is the (eventual) outcome of a question.
type AskResult struct {
	Status  string                    `json:"status"` // pending|done|error
	Answer  string                    `json:"answer,omitempty"`
	Hosts   []models.AssistantHostRow `json:"hosts,omitempty"`
	Error   string                    `json:"error,omitempty"`
	created time.Time
}

// Caller identity captured for RBAC-scoped tool execution in the background.
type Caller struct {
	UserID          uuid.UUID
	IsSuperAdmin    bool
	Username        string
	CanViewSessions bool // Session.Replay — gates the list_sessions tool
}

// Ask starts answering a question in the background and returns a poll id. Async
// because local LLM inference can exceed the HTTP request timeout.
func (s *Service) Ask(ctx context.Context, question string, who Caller) (string, bool) {
	cfg := s.settings(ctx)
	if !cfg.Enabled || cfg.OllamaURL == "" || cfg.Model == "" {
		return "", false
	}
	id := uuid.NewString()
	s.asks.Store(id, &AskResult{Status: "pending", created: time.Now()})
	go s.run(id, question, who, cfg)
	return id, true
}

// Result returns and (when finished) removes a pending result.
func (s *Service) Result(id string) (*AskResult, bool) {
	v, ok := s.asks.Load(id)
	if !ok {
		return nil, false
	}
	r := v.(*AskResult)
	if r.Status != "pending" {
		s.asks.Delete(id)
	}
	return r, true
}

func (s *Service) run(id, question string, who Caller, cfg Settings) {
	ctx, cancel := context.WithTimeout(context.Background(), askTimeout)
	defer cancel()
	s.cleanup()

	answer, hosts, err := s.converse(ctx, cfg, question, who)
	if err != nil {
		s.log.Warn("assistant ask failed", "user", who.Username, "err", err)
		s.asks.Store(id, &AskResult{Status: "error", Error: friendlyErr(err), created: time.Now()})
		return
	}
	s.asks.Store(id, &AskResult{Status: "done", Answer: answer, Hosts: hosts, created: time.Now()})
}

// converse runs the tool-calling loop: the model picks query_hosts + filters, we
// run the RBAC-scoped query, feed results back, and the model narrates.
func (s *Service) converse(ctx context.Context, cfg Settings, question string, who Caller) (string, []models.AssistantHostRow, error) {
	client := newOllama(cfg.OllamaURL)
	messages := []chatMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: question},
	}
	var collected []models.AssistantHostRow

	for i := 0; i < maxToolIterations; i++ {
		resp, err := client.chat(ctx, chatRequest{Model: cfg.Model, Messages: messages, Tools: tools})
		if err != nil {
			return "", nil, err
		}
		msg := resp.Message
		if len(msg.ToolCalls) == 0 {
			return strings.TrimSpace(msg.Content), collected, nil
		}
		messages = append(messages, msg)
		for _, tc := range msg.ToolCalls {
			var result any
			switch tc.Function.Name {
			case "query_hosts":
				rows := s.runQueryHosts(ctx, tc.Function.Arguments, who)
				collected = rows
				result = map[string]any{"count": len(rows), "hosts": rows}
			case "list_sessions":
				result = s.runListSessions(ctx, who)
			case "host_detail":
				result = s.runHostDetail(ctx, tc.Function.Arguments, who)
			default:
				result = map[string]any{"error": "unknown tool"}
			}
			payload, _ := json.Marshal(result)
			messages = append(messages, chatMessage{Role: "tool", Content: string(payload)})
		}
	}
	// Ran out of iterations; summarize from what we have.
	return "I couldn't fully resolve that. Here are the hosts I found.", collected, nil
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

func (s *Service) runListSessions(ctx context.Context, who Caller) any {
	if !who.CanViewSessions && !who.IsSuperAdmin {
		return map[string]any{"error": "you do not have permission to view sessions"}
	}
	rows, err := s.store.ActiveSSHSessions(ctx, 200)
	if err != nil {
		s.log.Warn("assistant list_sessions", "err", err)
		return map[string]any{"error": "could not list sessions"}
	}
	type sess struct {
		Username  string `json:"username"`
		Hostname  string `json:"hostname"`
		ClientIP  string `json:"clientIp,omitempty"`
		StartedAt string `json:"startedAt"`
	}
	out := make([]sess, 0, len(rows))
	for _, r := range rows {
		out = append(out, sess{Username: r.Username, Hostname: r.Hostname, ClientIP: r.ClientIP, StartedAt: r.StartedAt.Format(time.RFC3339)})
	}
	return map[string]any{"count": len(out), "sessions": out}
}

func (s *Service) runHostDetail(ctx context.Context, raw json.RawMessage, who Caller) any {
	var a hostDetailArgs
	_ = json.Unmarshal(raw, &a)
	if a.Hostname == "" {
		return map[string]any{"error": "hostname is required"}
	}
	host, err := s.store.HostByHostname(ctx, a.Hostname)
	if err != nil {
		return map[string]any{"error": "no host named " + a.Hostname}
	}
	if !who.IsSuperAdmin {
		ok, err := s.store.UserCanAccessHost(ctx, who.UserID, host.ID)
		if err != nil || !ok {
			return map[string]any{"error": "you do not have access to that host"}
		}
	}
	// Return the host with details; internal ids are harmless and ignored.
	return host
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
