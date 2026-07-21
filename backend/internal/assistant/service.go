// Package assistant implements a read-only, RBAC-scoped natural-language query
// layer over fleet data, backed by a local Ollama instance. The model only ever
// calls a curated query tool (it cannot run SQL or act on hosts); every answer
// is grounded in the real rows returned by that tool.
package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/aiaction"
	"github.com/fleet-terminal/backend/internal/insights"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

const (
	maxToolIterations = 8
	askTimeout        = 5 * time.Minute
	// maxConversationTurns bounds how many prior user/assistant exchanges are
	// carried as context into a follow-up question, so "what about db-02?" works
	// without letting history grow unbounded and bloat the local model's context.
	maxConversationTurns = 6
	conversationTTL      = 30 * time.Minute
)

// Service orchestrates assistant conversations.
type Service struct {
	store           *store.Store
	log             *slog.Logger
	insights        *insights.Service  // grounds the fleet_insights tool (what's-wrong / capacity)
	metricRetention time.Duration      // caps the host_metric_history window (0 = history disabled)
	actions         *aiaction.Registry // proposes guarded actions (propose_* tools); nil disables them
	asks            sync.Map           // id -> *AskResult (pointer replaced atomically on completion)
	convos          sync.Map           // conversationID -> *conversation (multi-turn memory)
}

// conversation is the trimmed running memory for one Ask thread: alternating
// user/assistant messages (no system prompt, no per-turn tool traffic), so a
// follow-up question can reference earlier ones. Scoped to its owner.
type conversation struct {
	mu      sync.Mutex
	owner   uuid.UUID
	history []chatMessage
	updated time.Time
}

func New(st *store.Store, log *slog.Logger, ins *insights.Service, metricRetention time.Duration, actions *aiaction.Registry) *Service {
	return &Service{store: st, log: log, insights: ins, metricRetention: metricRetention, actions: actions}
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
// can render a trend chart beneath the answer. Metrics narrows which series the
// question was about (subset of disk/memory/load; empty = all).
type MetricHistory struct {
	Hostname      string                     `json:"hostname"`
	WindowHours   int                        `json:"windowHours"`
	BucketMinutes int                        `json:"bucketMinutes"`
	Metrics       []string                   `json:"metrics,omitempty"`
	Points        []store.MetricHistoryPoint `json:"points"`
}

// TableColumn is one column of a generic assistant result table. Kind tells the
// UI how to format the raw string value ("" = text, "time" = RFC 3339 timestamp,
// "bytes" = byte count).
type TableColumn struct {
	Label string `json:"label"`
	Kind  string `json:"kind,omitempty"`
}

// AssistantTable is a generic tabular result (audit events, schedules, past
// sessions, file transfers...) the UI renders beneath the answer.
type AssistantTable struct {
	Title   string        `json:"title"`
	Columns []TableColumn `json:"columns"`
	Rows    [][]string    `json:"rows"`
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
	Table    *AssistantTable           `json:"table,omitempty"`
	Sources  []DocSource               `json:"sources,omitempty"`
	Actions  []models.AssistantAction  `json:"actions,omitempty"`
	Error    string                    `json:"error,omitempty"`
	created  time.Time
	owner    uuid.UUID // the user who asked; only they may read the result
}

// answerData bundles structured tool output collected during a conversation.
type answerData struct {
	hosts           []models.AssistantHostRow
	sessions        []SessionRow
	host            *models.Host
	history         *MetricHistory
	table           *AssistantTable
	docSources      []DocSource
	proposedActions []models.AssistantAction
}

// Caller identity captured for RBAC-scoped tool execution in the background.
type Caller struct {
	UserID           uuid.UUID
	IsSuperAdmin     bool
	Username         string
	CanViewSessions  bool // Session.Replay — gates list_sessions + session_history
	CanViewScans     bool // Host.Scan — gates the recent_scans tool
	CanViewRuns      bool // Playbook.Run — gates the recent_playbook_runs tool
	CanViewAudit     bool // Audit.View — gates the audit_log tool
	CanViewSchedules bool // Schedule.Manage — gates the list_schedules tool
	CanViewTransfers bool // File.Transfer — gates the recent_file_transfers tool
	CanViewCommands  bool // Command.Run — gates the recent_commands tool
	CanAct           bool // Assistant.Act — gates the propose_* action tools
	// Perms is a snapshot of the caller's permission set, used to authorize a
	// proposed action at propose time (execution re-checks the live principal).
	Perms map[string]bool
}

// Can reports whether the caller holds a permission, mirroring auth.Principal.Has.
func (c Caller) Can(perm string) bool {
	if c.IsSuperAdmin || c.Perms["Admin.All"] {
		return true
	}
	return c.Perms[perm]
}

// Ask starts answering a question in the background and returns a poll id plus
// the conversation id to carry into follow-up questions (a new one is minted when
// conversationID is empty). Async because local LLM inference can exceed the HTTP
// request timeout.
func (s *Service) Ask(ctx context.Context, question, conversationID string, who Caller) (askID, convoID string, ok bool) {
	cfg := s.settings(ctx)
	if !cfg.Enabled || cfg.OllamaURL == "" || cfg.Model == "" {
		return "", "", false
	}
	convoID = conversationID
	if convoID == "" {
		convoID = uuid.NewString()
	}
	askID = uuid.NewString()
	s.asks.Store(askID, &AskResult{Status: "pending", created: time.Now(), owner: who.UserID})
	go s.run(askID, convoID, question, who, cfg)
	return askID, convoID, true
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

func (s *Service) run(id, convoID, question string, who Caller, cfg Settings) {
	ctx, cancel := context.WithTimeout(context.Background(), askTimeout)
	defer cancel()
	s.cleanup()

	answer, data, err := s.converse(ctx, cfg, convoID, question, who)
	if err != nil {
		s.log.Warn("assistant ask failed", "user", who.Username, "err", err)
		s.asks.Store(id, &AskResult{Status: "error", Error: friendlyErr(err), created: time.Now(), owner: who.UserID})
		return
	}
	s.asks.Store(id, &AskResult{
		Status: "done", Answer: answer,
		Hosts: data.hosts, Sessions: data.sessions, Host: data.host, History: data.history,
		Table: data.table, Sources: data.docSources, Actions: data.proposedActions,
		created: time.Now(), owner: who.UserID,
	})
}

// converse runs the tool-calling loop: the model picks query_hosts + filters, we
// run the RBAC-scoped query, feed results back, and the model narrates.
func (s *Service) converse(ctx context.Context, cfg Settings, convoID, question string, who Caller) (string, answerData, error) {
	client := newOllama(cfg.OllamaURL)
	prior := s.priorMessages(convoID, who.UserID)
	messages := make([]chatMessage, 0, len(prior)+2)
	messages = append(messages, chatMessage{Role: "system", Content: systemPrompt})
	messages = append(messages, prior...)
	messages = append(messages, chatMessage{Role: "user", Content: question})
	var data answerData

	// Fast path: for a few unambiguous question shapes (who ran <command>, what are the
	// pending updates), run the correct tool DETERMINISTICALLY and have the model narrate
	// from that data with tools disabled — so a small local model can't mis-route (e.g.
	// answer "who ran df" with fleet health, or dump the whole host for an updates
	// question). The structured result still populates the UI. Anything not recognized
	// falls through to the normal model-driven loop below.
	if name, fargs, ok := fastPathTool(question); ok {
		var result any
		switch name {
		case "host_updates":
			tbl, payload := s.runHostUpdates(ctx, fargs, who)
			if tbl != nil {
				data.table = tbl
			}
			result = payload
		case "search_commands":
			tbl, payload := s.runSearchCommands(ctx, fargs, who)
			if tbl != nil {
				data.table = tbl
			}
			result = payload
		}
		if final, err := s.narrateFromData(ctx, client, cfg, messages, name, result); err == nil {
			s.remember(convoID, who.UserID, question, final)
			return final, data, nil
		}
		// On a narration failure, fall through to the normal loop rather than error out.
	}

	// Offer the action (propose_*) tools only to callers permitted to act and only
	// when the registry is wired; everyone else sees the read-only tool surface.
	toolset := tools
	if who.CanAct && s.actions != nil {
		toolset = append(append(make([]toolDef, 0, len(tools)+len(actionTools)), tools...), actionTools...)
	}

	for i := 0; i < maxToolIterations; i++ {
		resp, err := client.chat(ctx, chatRequest{Model: cfg.Model, Messages: messages, Tools: toolset})
		if err != nil {
			return "", data, err
		}
		msg := resp.Message
		if len(msg.ToolCalls) == 0 {
			final := strings.TrimSpace(msg.Content)
			s.remember(convoID, who.UserID, question, final)
			return final, data, nil
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
			case "host_updates":
				tbl, payload := s.runHostUpdates(ctx, tc.Function.Arguments, who)
				if tbl != nil {
					data.table = tbl
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
			case "recent_commands":
				tbl, payload := s.runRecentCommands(ctx, tc.Function.Arguments, who)
				if tbl != nil {
					data.table = tbl
				}
				result = payload
			case "search_commands":
				tbl, payload := s.runSearchCommands(ctx, tc.Function.Arguments, who)
				if tbl != nil {
					data.table = tbl
				}
				result = payload
			case "host_metric_history":
				hist, payload := s.runMetricHistory(ctx, tc.Function.Arguments, who)
				if hist != nil {
					data.history = hist
				}
				result = payload
			case "session_history":
				tbl, payload := s.runSessionHistory(ctx, tc.Function.Arguments, who)
				if tbl != nil {
					data.table = tbl
				}
				result = payload
			case "audit_log":
				tbl, payload := s.runAuditLog(ctx, tc.Function.Arguments, who)
				if tbl != nil {
					data.table = tbl
				}
				result = payload
			case "list_schedules":
				tbl, payload := s.runListSchedules(ctx, who)
				if tbl != nil {
					data.table = tbl
				}
				result = payload
			case "recent_file_transfers":
				tbl, payload := s.runFileTransfers(ctx, tc.Function.Arguments, who)
				if tbl != nil {
					data.table = tbl
				}
				result = payload
			case "fleet_insights":
				tbl, payload := s.runFleetInsights(ctx, who)
				if tbl != nil {
					data.table = tbl
				}
				result = payload
			case "search_docs":
				payload, sources := s.runSearchDocs(tc.Function.Arguments)
				if len(sources) > 0 {
					data.docSources = mergeSources(data.docSources, sources)
				}
				result = payload
			default:
				if kind, ok := actionToolKinds[tc.Function.Name]; ok {
					payload, action := s.proposeAction(ctx, who, kind, tc.Function.Arguments)
					if action != nil {
						data.proposedActions = append(data.proposedActions, *action)
					}
					result = payload
				} else {
					result = map[string]any{"error": "unknown tool"}
				}
			}
			payload, _ := json.Marshal(result)
			messages = append(messages, chatMessage{Role: "tool", Content: string(payload)})
		}
	}
	// Ran out of iterations; summarize from what we have.
	final := "I couldn't fully resolve that. Here is the data I found."
	s.remember(convoID, who.UserID, question, final)
	return final, data, nil
}

// narrateFromData asks the model to write the answer from a fast-path tool's result,
// with tools DISABLED so it can't mis-route to another tool. base is the built-up
// message history (system prompt + prior turns + the user question).
func (s *Service) narrateFromData(ctx context.Context, client *ollamaClient, cfg Settings, base []chatMessage, toolName string, result any) (string, error) {
	raw, _ := json.Marshal(result)
	msgs := append(append([]chatMessage(nil), base...), chatMessage{
		Role: "system",
		Content: fmt.Sprintf("The %s tool was already run for this question and returned this data:\n%s\n\n"+
			"Answer the user's question using ONLY this data. If it has no rows or is empty, say plainly "+
			"that nothing matched. Be concise and summarize — the full structured data is shown to the user "+
			"separately, so do not dump every row.", toolName, string(raw)),
	})
	resp, err := client.chat(ctx, chatRequest{Model: cfg.Model, Messages: msgs})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(resp.Message.Content), nil
}

// priorMessages returns the carried conversation history for convoID, but only if
// it belongs to this user (a client-supplied id for someone else's conversation
// is ignored, never leaked). Empty for a new or foreign conversation.
func (s *Service) priorMessages(convoID string, owner uuid.UUID) []chatMessage {
	v, ok := s.convos.Load(convoID)
	if !ok {
		return nil
	}
	c := v.(*conversation)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.owner != owner {
		return nil
	}
	return append([]chatMessage(nil), c.history...)
}

// remember appends this exchange to the conversation memory, creating it on first
// use and trimming to the most recent maxConversationTurns exchanges.
func (s *Service) remember(convoID string, owner uuid.UUID, question, answer string) {
	if convoID == "" || answer == "" {
		return
	}
	v, _ := s.convos.LoadOrStore(convoID, &conversation{owner: owner})
	c := v.(*conversation)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.owner != owner {
		return // id collision across users: never merge histories
	}
	c.history = append(c.history,
		chatMessage{Role: "user", Content: question},
		chatMessage{Role: "assistant", Content: answer})
	if max := maxConversationTurns * 2; len(c.history) > max {
		c.history = append([]chatMessage(nil), c.history[len(c.history)-max:]...)
	}
	c.updated = time.Now()
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

// runHostUpdates returns the pending-update package list (one host or all accessible
// hosts) as a focused table — the update-specific alternative to host_detail, which
// would render the whole host card. Scoped to the caller's accessible hosts.
func (s *Service) runHostUpdates(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	var a hostUpdatesArgs
	_ = json.Unmarshal(raw, &a)
	rows, err := s.store.HostUpdatePackagesForAssistant(ctx, who.UserID, who.IsSuperAdmin, strings.TrimSpace(a.Hostname), a.Limit)
	if err != nil {
		s.log.Warn("assistant host_updates", "err", err)
		return nil, map[string]any{"error": "could not list pending updates"}
	}
	tbl := &AssistantTable{
		Title:   "Pending updates",
		Columns: []TableColumn{{Label: "Host"}, {Label: "Package"}, {Label: "New version"}, {Label: "Security"}},
	}
	for _, r := range rows {
		sec := ""
		if r.Security {
			sec = "security"
		}
		tbl.Rows = append(tbl.Rows, []string{r.Hostname, r.Package, r.NewVersion, sec})
	}
	if len(rows) == 0 {
		tbl = nil
	}
	return tbl, map[string]any{"count": len(rows), "updates": rows}
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

// runRecentCommands returns ad-hoc Run-Command executions (gated by Command.Run) — the
// authoritative "who ran which command" record for Fleet-issued commands. It excludes
// the command output bodies (kept out of the model context) and optionally filters by a
// command substring or target name.
func (s *Service) runRecentCommands(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	if !who.CanViewCommands && !who.IsSuperAdmin {
		return nil, map[string]any{"error": "you do not have permission to view command runs"}
	}
	var a recentCommandsArgs
	_ = json.Unmarshal(raw, &a)
	limit := a.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	// Fetch a generous window, then apply the (optional) substring/target filters and
	// cap to the requested limit.
	runs, err := s.store.ListCommandRuns(ctx, 200)
	if err != nil {
		s.log.Warn("assistant recent_commands", "err", err)
		return nil, map[string]any{"error": "could not list command runs"}
	}
	contains := strings.ToLower(strings.TrimSpace(a.Contains))
	host := strings.ToLower(strings.TrimSpace(a.Hostname))
	tbl := &AssistantTable{
		Title: "Command runs",
		Columns: []TableColumn{{Label: "Time", Kind: "time"}, {Label: "Requester"}, {Label: "Target"},
			{Label: "Command"}, {Label: "Status"}, {Label: "Exit"}},
	}
	type cmdRow struct {
		Command    string     `json:"command"`
		Requester  string     `json:"requester"`
		Target     string     `json:"target"`
		HostCount  int        `json:"hostCount"`
		Status     string     `json:"status"`
		ExitCode   *int       `json:"exitCode,omitempty"`
		RanAt      time.Time  `json:"ranAt"`
		FinishedAt *time.Time `json:"finishedAt,omitempty"`
	}
	var out []cmdRow
	for _, r := range runs {
		if contains != "" && !strings.Contains(strings.ToLower(r.Command), contains) {
			continue
		}
		if host != "" && !strings.Contains(strings.ToLower(r.TargetName), host) {
			continue
		}
		exit := ""
		if r.ExitCode != nil {
			exit = fmt.Sprint(*r.ExitCode)
		}
		tbl.Rows = append(tbl.Rows, []string{tableTime(r.CreatedAt), r.Requester, r.TargetName,
			r.Command, r.Status, exit})
		out = append(out, cmdRow{
			Command: r.Command, Requester: r.Requester, Target: r.TargetName, HostCount: r.HostCount,
			Status: r.Status, ExitCode: r.ExitCode, RanAt: r.CreatedAt, FinishedAt: r.FinishedAt,
		})
		if len(out) >= limit {
			break
		}
	}
	if len(out) == 0 {
		tbl = nil
	}
	return tbl, map[string]any{"count": len(out), "commands": out}
}

// runSearchCommands searches the reconstructed commands typed in recorded SSH sessions
// (gated by Session.Replay, scoped to the caller's accessible hosts). Best-effort — the
// payload flags it so the model qualifies its answer.
func (s *Service) runSearchCommands(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	if !who.CanViewSessions && !who.IsSuperAdmin {
		return nil, map[string]any{"error": "you do not have permission to view session recordings"}
	}
	var a searchCommandsArgs
	_ = json.Unmarshal(raw, &a)
	if strings.TrimSpace(a.Query) == "" {
		return nil, map[string]any{"error": "a search query is required"}
	}
	rows, err := s.store.SearchSessionCommands(ctx, who.UserID, who.IsSuperAdmin, strings.TrimSpace(a.Query), strings.TrimSpace(a.Hostname), a.Limit)
	if err != nil {
		s.log.Warn("assistant search_commands", "err", err)
		return nil, map[string]any{"error": "could not search session commands"}
	}
	tbl := &AssistantTable{
		Title:   "Typed commands (from session recordings)",
		Columns: []TableColumn{{Label: "Time", Kind: "time"}, {Label: "User"}, {Label: "Host"}, {Label: "Command (typed)"}},
	}
	for _, r := range rows {
		tbl.Rows = append(tbl.Rows, []string{tableTime(r.At), r.Username, r.Hostname, r.Command})
	}
	if len(rows) == 0 {
		tbl = nil
	}
	return tbl, map[string]any{
		"count":   len(rows),
		"matches": rows,
		"caveat":  "Reconstructed from terminal keystrokes (best-effort): tab-completion and history-recalled commands may be missing or partial, and only RECORDED sessions are covered. Present as what was typed, not a guaranteed executed-command log.",
	}
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
	metrics := normalizeMetrics(a.Metrics)
	hist := &MetricHistory{
		Hostname:      host.Hostname,
		WindowHours:   int(window / time.Hour),
		BucketMinutes: int(bucket / time.Minute),
		Metrics:       metrics,
		Points:        points,
	}
	payload := map[string]any{
		"hostname":      hist.Hostname,
		"windowHours":   hist.WindowHours,
		"bucketMinutes": hist.BucketMinutes,
		"count":         len(points),
		"points":        filterPoints(points, metrics),
	}
	if len(points) == 0 {
		payload["note"] = "no metric history recorded for this host in the requested window (it may have been enrolled recently, or history collection just started)"
		return nil, payload // nothing to chart
	}
	return hist, payload
}

// normalizeMetrics validates the model's metric selection down to the known
// series names; nil means "all metrics".
func normalizeMetrics(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range in {
		m = strings.ToLower(strings.TrimSpace(m))
		switch m {
		case "disk", "memory", "load":
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

// filterPoints strips the series the question was not about from the payload
// fed to the model, so the answer (and the model's attention) stays on what was
// asked. The UI chart filters independently via MetricHistory.Metrics.
func filterPoints(points []store.MetricHistoryPoint, metrics []string) any {
	if len(metrics) == 0 {
		return points
	}
	want := map[string]bool{}
	for _, m := range metrics {
		want[m] = true
	}
	out := make([]map[string]any, 0, len(points))
	for _, p := range points {
		row := map[string]any{"t": p.Time, "samples": p.Samples}
		if want["disk"] {
			putFloat(row, "diskFreePctAvg", p.DiskFreePctAvg)
			putFloat(row, "diskFreePctMin", p.DiskFreePctMin)
		}
		if want["memory"] {
			putFloat(row, "memUsedPctAvg", p.MemUsedPctAvg)
			putFloat(row, "memUsedPctMax", p.MemUsedPctMax)
		}
		if want["load"] {
			putFloat(row, "loadPerCoreAvg", p.LoadPerCoreAvg)
			putFloat(row, "loadPerCoreMax", p.LoadPerCoreMax)
		}
		out = append(out, row)
	}
	return out
}

func putFloat(row map[string]any, key string, v *float64) {
	if v != nil {
		row[key] = *v
	}
}

// windowSince converts an "hours back" tool argument into a start time,
// applying the tool's default and the shared 30-day cap.
func windowSince(hours, def int) time.Time {
	if hours <= 0 {
		hours = def
	}
	if hours > 720 {
		hours = 720
	}
	return time.Now().Add(-time.Duration(hours) * time.Hour)
}

func tableTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func tableTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return tableTime(*t)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// runSessionHistory returns past + active SSH sessions (gated like the sessions
// page) as a UI table plus the model payload.
func (s *Service) runSessionHistory(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	if !who.CanViewSessions && !who.IsSuperAdmin {
		return nil, map[string]any{"error": "you do not have permission to view session history"}
	}
	var a sessionHistoryArgs
	_ = json.Unmarshal(raw, &a)
	rows, err := s.store.RecentSSHSessionsForAssistant(ctx, who.UserID, who.IsSuperAdmin,
		a.Hostname, a.Username, windowSince(a.Hours, 48), a.Limit)
	if err != nil {
		s.log.Warn("assistant session_history", "err", err)
		return nil, map[string]any{"error": "could not list session history"}
	}
	tbl := &AssistantTable{
		Title: "SSH sessions",
		Columns: []TableColumn{{Label: "User"}, {Label: "Host"}, {Label: "Client IP"},
			{Label: "Status"}, {Label: "Started", Kind: "time"}, {Label: "Ended", Kind: "time"}},
	}
	for _, r := range rows {
		tbl.Rows = append(tbl.Rows, []string{r.Username, r.Hostname, r.ClientIP,
			r.Status, tableTime(r.StartedAt), tableTimePtr(r.EndedAt)})
	}
	if len(rows) == 0 {
		tbl = nil
	}
	return tbl, map[string]any{"count": len(rows), "sessions": rows}
}

// runAuditLog returns recent audit events (gated by Audit.View) as a UI table
// plus the model payload.
func (s *Service) runAuditLog(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	if !who.CanViewAudit && !who.IsSuperAdmin {
		return nil, map[string]any{"error": "you do not have permission to view the audit log"}
	}
	var a auditLogArgs
	_ = json.Unmarshal(raw, &a)
	rows, err := s.store.RecentAuditForAssistant(ctx, a.ActionContains, a.ActorContains,
		windowSince(a.Hours, 24), a.Limit)
	if err != nil {
		s.log.Warn("assistant audit_log", "err", err)
		return nil, map[string]any{"error": "could not list audit events"}
	}
	tbl := &AssistantTable{
		Title: "Audit events",
		Columns: []TableColumn{{Label: "Time", Kind: "time"}, {Label: "Actor"}, {Label: "Action"},
			{Label: "Target"}, {Label: "IP"}, {Label: "Detail"}},
	}
	for _, r := range rows {
		tbl.Rows = append(tbl.Rows, []string{tableTime(r.Time), r.Actor, r.Action,
			r.TargetKind, r.IP, r.Detail})
	}
	if len(rows) == 0 {
		tbl = nil
	}
	return tbl, map[string]any{"count": len(rows), "events": rows}
}

// runListSchedules returns the recurring scan/playbook schedules (gated by
// Schedule.Manage) as a UI table plus the model payload.
func (s *Service) runListSchedules(ctx context.Context, who Caller) (*AssistantTable, any) {
	if !who.CanViewSchedules && !who.IsSuperAdmin {
		return nil, map[string]any{"error": "you do not have permission to view schedules"}
	}
	scheds, err := s.store.ListSchedules(ctx)
	if err != nil {
		s.log.Warn("assistant list_schedules", "err", err)
		return nil, map[string]any{"error": "could not list schedules"}
	}
	rows := make([]models.AssistantScheduleRow, 0, len(scheds))
	for _, sc := range scheds {
		target := sc.TargetKind
		if sc.TargetName != "" {
			target += " " + sc.TargetName
		}
		rows = append(rows, models.AssistantScheduleRow{
			Name: sc.Name, Kind: sc.Kind, Enabled: sc.Enabled, Target: target,
			Recurrence: recurrenceSummary(sc.Recurrence),
			LastRunAt:  sc.LastRunAt, LastStatus: sc.LastStatus,
			NextRunAt: sc.NextRunAt, Running: sc.Running,
		})
	}
	tbl := &AssistantTable{
		Title: "Schedules",
		Columns: []TableColumn{{Label: "Name"}, {Label: "Kind"}, {Label: "Enabled"},
			{Label: "Target"}, {Label: "Recurrence"}, {Label: "Last run", Kind: "time"},
			{Label: "Last status"}, {Label: "Next run", Kind: "time"}},
	}
	for _, r := range rows {
		tbl.Rows = append(tbl.Rows, []string{r.Name, r.Kind, yesNo(r.Enabled), r.Target,
			r.Recurrence, tableTimePtr(r.LastRunAt), r.LastStatus, tableTimePtr(r.NextRunAt)})
	}
	if len(rows) == 0 {
		tbl = nil
	}
	return tbl, map[string]any{"count": len(rows), "schedules": rows}
}

// recurrenceSummary renders a schedule's recurrence in words for the model/UI.
func recurrenceSummary(r models.Recurrence) string {
	switch r.Type {
	case "interval":
		if r.EveryMinutes > 0 && r.EveryMinutes%60 == 0 {
			return fmt.Sprintf("every %dh", r.EveryMinutes/60)
		}
		return fmt.Sprintf("every %dm", r.EveryMinutes)
	case "daily":
		return "daily at " + r.TimeOfDay
	case "weekly":
		return "weekly on " + time.Weekday(r.Weekday).String() + " at " + r.TimeOfDay
	}
	return r.Type
}

// runFileTransfers returns recent SFTP transfers (gated like the transfers
// panel, scoped to accessible hosts) as a UI table plus the model payload.
func (s *Service) runFileTransfers(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	if !who.CanViewTransfers && !who.IsSuperAdmin {
		return nil, map[string]any{"error": "you do not have permission to view file transfers"}
	}
	var a fileTransfersArgs
	_ = json.Unmarshal(raw, &a)
	rows, err := s.store.RecentSFTPTransfersForAssistant(ctx, who.UserID, who.IsSuperAdmin,
		a.Hostname, windowSince(a.Hours, 168), a.Limit)
	if err != nil {
		s.log.Warn("assistant recent_file_transfers", "err", err)
		return nil, map[string]any{"error": "could not list file transfers"}
	}
	tbl := &AssistantTable{
		Title: "File transfers",
		Columns: []TableColumn{{Label: "Time", Kind: "time"}, {Label: "User"}, {Label: "Host"},
			{Label: "Direction"}, {Label: "Path"}, {Label: "Size", Kind: "bytes"}, {Label: "Status"}},
	}
	for _, r := range rows {
		tbl.Rows = append(tbl.Rows, []string{tableTime(r.Time), r.Username, r.Hostname,
			r.Direction, r.Path, fmt.Sprint(r.SizeBytes), r.Status})
	}
	if len(rows) == 0 {
		tbl = nil
	}
	return tbl, map[string]any{"count": len(rows), "transfers": rows}
}

// runFleetInsights returns the computed fleet-health issues for the caller's
// accessible hosts (offline, low/filling disk with runway, high load/memory,
// pending updates), grounding open-ended "what's wrong / when will X fill up"
// answers in the same deterministic engine the dashboard uses.
func (s *Service) runFleetInsights(ctx context.Context, who Caller) (*AssistantTable, any) {
	if s.insights == nil {
		return nil, map[string]any{"error": "insights are not available"}
	}
	items, err := s.insights.Compute(ctx, who.UserID, who.IsSuperAdmin)
	if err != nil {
		s.log.Warn("assistant fleet_insights", "err", err)
		return nil, map[string]any{"error": "could not compute insights"}
	}
	if len(items) == 0 {
		return nil, map[string]any{"count": 0, "insights": []any{}, "note": "no issues detected across the accessible fleet"}
	}
	tbl := &AssistantTable{
		Title:   "Fleet insights",
		Columns: []TableColumn{{Label: "Severity"}, {Label: "Host"}, {Label: "Issue"}, {Label: "Detail"}},
	}
	for _, it := range items {
		tbl.Rows = append(tbl.Rows, []string{it.Severity, it.Hostname, it.Title, it.Detail})
	}
	return tbl, map[string]any{"count": len(items), "insights": items}
}

type searchDocsArgs struct {
	Query string `json:"query"`
}

// runSearchDocs retrieves the documentation sections most relevant to the query
// (BM25 over the embedded curated docs) and returns them to the model, plus the
// citations for the UI. Read-only; available to anyone with Assistant.Use.
func (s *Service) runSearchDocs(raw json.RawMessage) (any, []DocSource) {
	var a searchDocsArgs
	_ = json.Unmarshal(raw, &a)
	if strings.TrimSpace(a.Query) == "" {
		return map[string]any{"error": "query is required"}, nil
	}
	secs := searchDocs(a.Query, 4)
	if len(secs) == 0 {
		return map[string]any{"results": []any{}, "note": "no matching documentation section found"}, nil
	}
	results := make([]map[string]any, 0, len(secs))
	sources := make([]DocSource, 0, len(secs))
	for _, sec := range secs {
		results = append(results, map[string]any{
			"doc":     sec.DocTitle,
			"heading": sec.Heading,
			"content": clipText(sec.Text, 900),
		})
		sources = append(sources, DocSource{DocTitle: sec.DocTitle, Heading: sec.Heading, Slug: sec.DocSlug, Anchor: sec.Anchor})
	}
	return map[string]any{"results": results}, sources
}

// proposeAction stages a guarded action from a propose_* tool call. It never
// executes anything — it validates + authorizes + persists a pending proposal the
// user must confirm. Returns the tool result for the model and the proposal (if
// any) to surface in the UI.
func (s *Service) proposeAction(ctx context.Context, who Caller, kind string, raw json.RawMessage) (any, *models.AssistantAction) {
	if s.actions == nil {
		return map[string]any{"error": "actions are not enabled"}, nil
	}
	actor := aiaction.Actor{UserID: who.UserID, Username: who.Username, IsSuper: who.IsSuperAdmin, Can: who.Can}
	action, err := s.actions.Propose(ctx, actor, kind, raw)
	if err != nil {
		var pe *aiaction.PermError
		if errors.As(err, &pe) {
			return map[string]any{"error": "the user lacks permission for this action (" + pe.Permission + ")"}, nil
		}
		return map[string]any{"error": err.Error()}, nil
	}
	requiresApproval := action.Risk != "safe"
	note := "Prepared this action but did NOT run it — the user must confirm it first."
	if requiresApproval {
		note = "Prepared this GUARDED action but did NOT run it. It cannot run on the user's confirm alone — after the user requests approval, a second person must approve it."
	}
	return map[string]any{
		"status":           "proposed",
		"note":             note + " Tell the user plainly what you are proposing; never claim it is already done.",
		"preview":          action.Preview,
		"requiresApproval": requiresApproval,
		"actionId":         action.ID.String(),
	}, action
}

// mergeSources appends new citations, de-duplicating by slug+anchor so repeated
// search_docs calls in one turn don't list the same section twice.
func mergeSources(existing, add []DocSource) []DocSource {
	seen := make(map[string]bool, len(existing))
	for _, s := range existing {
		seen[s.Slug+"#"+s.Anchor] = true
	}
	for _, s := range add {
		if key := s.Slug + "#" + s.Anchor; !seen[key] {
			seen[key] = true
			existing = append(existing, s)
		}
	}
	return existing
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
	convoCutoff := time.Now().Add(-conversationTTL)
	s.convos.Range(func(k, v any) bool {
		if c, ok := v.(*conversation); ok {
			c.mu.Lock()
			stale := c.updated.Before(convoCutoff)
			c.mu.Unlock()
			if stale {
				s.convos.Delete(k)
			}
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
