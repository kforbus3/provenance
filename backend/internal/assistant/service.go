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
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/aiaction"
	"github.com/fleet-terminal/backend/internal/insights"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
	"github.com/fleet-terminal/backend/internal/tenant"
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
	UserID            uuid.UUID
	IsSuperAdmin      bool
	Username          string
	CanViewSessions   bool // Session.Replay — gates list_sessions + session_history
	CanViewScans      bool // Host.Scan — gates the recent_scans tool
	CanViewRuns       bool // Playbook.Run — gates the recent_playbook_runs tool
	CanViewAudit      bool // Audit.View — gates the audit_log tool
	CanViewSchedules  bool // Schedule.Manage — gates the list_schedules tool
	CanViewTransfers  bool // File.Transfer — gates the recent_file_transfers tool
	CanViewCommands   bool // Command.Run — gates the recent_commands tool
	CanViewUsers      bool // User.Edit — gates the list_users tool
	CanViewApprovals  bool // Approval.Request/Decide — gates the list_approvals tool
	CanViewCluster    bool // System.Configure — gates the cluster section of platform_status
	CanViewEnrollment bool // Host.Enroll — gates the enrollment section of platform_status
	CanAct            bool // Assistant.Act — gates the propose_* action tools
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
	// Capture the caller's tenant scope from the request context. The work runs in a
	// background context (LLM inference outlives the request), so without this the
	// pool's RLS hook would see an unmarked context and, under multi-tenancy, deny
	// every row (fail-closed) — the assistant would answer nothing. Propagating the
	// caller's own tenant makes the background queries behave exactly like a
	// synchronous request: scoped to that tenant, never cross-tenant. With MT off the
	// value is still a tenant id but the pool ignores it and uses Bypass, unchanged.
	tenantScope := tenant.GUCValue(ctx)
	go s.run(askID, convoID, question, who, cfg, tenantScope)
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

func (s *Service) run(id, convoID, question string, who Caller, cfg Settings, tenantScope string) {
	ctx, cancel := context.WithTimeout(context.Background(), askTimeout)
	defer cancel()
	// Re-apply the caller's tenant scope so RLS filters every query this background
	// run makes to the caller's tenant (see Ask). Empty only if the caller was
	// somehow unauthenticated, in which case fail-closed denial is the safe outcome.
	if tenantScope != "" {
		ctx = tenant.WithID(ctx, tenantScope)
	}
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
	sysPrompt := systemPrompt
	if tz := s.store.DisplayTimezone(ctx); tz != "" {
		// The operator has a configured display timezone. Tool results carry absolute
		// timestamps with an explicit UTC offset, and recurrence strings ("daily at
		// 03:00") are already expressed in this zone — tell the model so it reports
		// times in the operator's zone instead of defaulting to UTC.
		sysPrompt += fmt.Sprintf("\n\nThe operator's display timezone is %s. Report all times in %s. "+
			"Absolute timestamps in tool results include a UTC offset — convert them to %s. A schedule's "+
			"recurrence time (e.g. \"daily at 03:00\") is ALREADY in %s, so state it as-is in %s; never label it UTC.",
			tz, tz, tz, tz, tz)
	}
	messages = append(messages, chatMessage{Role: "system", Content: sysPrompt})
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
		var directAnswer string // when set, returned verbatim (the tool KNOWS the exact
		// answer, e.g. a host list or a change breakdown — the LLM is unreliable at
		// enumerating/counting, so we build the answer in code and skip narration).
		handled := true
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
		case "host_availability":
			tbl, payload := s.runHostAvailability(ctx, fargs, who)
			if tbl != nil {
				data.table = tbl
			}
			result = payload
		case "capacity_outlook":
			tbl, payload := s.runCapacityOutlook(ctx, fargs, who)
			if tbl != nil {
				data.table = tbl
			}
			result = payload
		case "security_events":
			tbl, payload := s.runSecurityEvents(ctx, fargs, who)
			if tbl != nil {
				data.table = tbl
			}
			result = payload
		case "vulnerabilities":
			tbl, payload := s.runVulnerabilities(ctx, fargs, who)
			if tbl != nil {
				data.table = tbl
			}
			result = payload
		case "list_users":
			tbl, payload := s.runListUsers(ctx, fargs, who)
			if tbl != nil {
				data.table = tbl
			}
			result = payload
		case "query_hosts":
			rows := s.runQueryHosts(ctx, fargs, who)
			data.hosts = rows // full rows still drive the UI host list
			// A disk-free filter question ("which hosts have less than N% disk free") is a
			// pure list — the tool knows exactly which hosts match. Build the answer
			// deterministically (count + EVERY host with its %), because the model
			// truncates and miscounts long lists even from a compact projection.
			if da := diskFreeDirectAnswer(question, fargs, rows); da != "" {
				directAnswer = da
			} else {
				compact := make([]map[string]any, len(rows))
				for i, r := range rows {
					compact[i] = map[string]any{
						"hostname": r.Hostname, "status": r.Status,
						"diskFreePct": r.MinDiskFreePct, "memUsedPct": r.MemUsedPct,
						"updatesAvailable": r.UpdatesAvailable, "securityUpdates": r.SecurityUpdates,
					}
				}
				result = map[string]any{"count": len(rows), "hosts": compact}
			}
		case "host_detail":
			host, payload := s.hostDetail(ctx, fargs, who)
			if host != nil {
				data.host = host
			}
			result = payload
		case "list_schedules":
			tbl, payload := s.runListSchedules(ctx, who)
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
		case "session_history":
			fargs = s.calendarAdjustHours(ctx, question, fargs)
			tbl, payload := s.runSessionHistory(ctx, fargs, who)
			if tbl != nil {
				data.table = tbl
			}
			directAnswer = s.sessionDirectAnswer(ctx, fargs, payload)
			result = payload
		case "recent_activity_failures":
			result = s.runActivityFailures(ctx, who)
		case "audit_log":
			tbl, payload := s.runAuditLog(ctx, fargs, who)
			if tbl != nil {
				data.table = tbl
			}
			// "What changed" is a breakdown the tool already computed (changesByAction,
			// de-noised). Build it deterministically so the model can't re-introduce the
			// routine noise or drop changes.
			directAnswer = auditChangesDirectAnswer(question, payload)
			result = payload
		case "host_metric_history":
			hist, payload := s.runMetricHistory(ctx, fargs, who)
			if hist != nil {
				data.history = hist
				directAnswer = metricTrendDirectAnswer(hist) // deterministic trend sentence
			}
			result = payload
		default:
			// fastPathTool routed to a tool with no dispatch here — a wiring bug that
			// would otherwise narrate empty data (a false "nothing found"). Fall through
			// to the model-driven loop, which handles every tool, instead.
			handled = false
			s.log.Warn("assistant fast-path tool has no dispatch handler; deferring to model", "tool", name)
		}
		if directAnswer != "" {
			s.remember(convoID, who.UserID, question, directAnswer)
			return directAnswer, data, nil
		}
		if handled {
			if final, err := s.narrateFromData(ctx, client, cfg, messages, name, result); err == nil && strings.TrimSpace(final) != "" {
				s.remember(convoID, who.UserID, question, final)
				return final, data, nil
			}
		}
		// Not handled, or narration failed/empty: fall through to the normal loop.
	}

	// Offer the action (propose_*) tools only to callers permitted to act and only
	// when the registry is wired; everyone else sees the read-only tool surface.
	toolset := tools
	if who.CanAct && s.actions != nil {
		toolset = append(append(make([]toolDef, 0, len(tools)+len(actionTools)), tools...), actionTools...)
	}

	toolsUsed := false
	for i := 0; i < maxToolIterations; i++ {
		resp, err := client.chat(ctx, chatRequest{Model: cfg.Model, Messages: messages, Tools: toolset, Options: deterministicOptions()})
		if err != nil {
			return "", data, err
		}
		msg := resp.Message
		if len(msg.ToolCalls) == 0 {
			final := strings.TrimSpace(msg.Content)
			// If tools gathered data, regenerate the answer with a short scope reminder
			// placed right before generation. Small models follow a late, focused
			// instruction far more reliably than the same rules buried in the long system
			// prompt — without this they enumerate every row and append recommendations
			// even when told not to.
			if toolsUsed && final != "" {
				if refined := s.refineFinalAnswer(ctx, client, cfg, messages); refined != "" {
					final = refined
				}
			}
			if final == "" {
				// The model returned an empty message (observed with small models when
				// they can't map a question to a tool). Give a useful fallback rather
				// than a blank answer: if a tool did populate data, note it; otherwise
				// say plainly that Fleet has no data for this.
				if data.table != nil || data.host != nil || data.history != nil || len(data.hosts) > 0 {
					final = "Here is what I found for that (see the details below)."
				} else {
					final = "I couldn't find anything in Fleet that answers that. Fleet may not collect that data — it tracks host status, inventory, metrics, updates, vulnerabilities, sessions, audit and auth events, scans, playbook runs, users, and approvals."
				}
			}
			s.remember(convoID, who.UserID, question, final)
			return final, data, nil
		}
		toolsUsed = true
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
			case "host_availability":
				tbl, payload := s.runHostAvailability(ctx, tc.Function.Arguments, who)
				if tbl != nil {
					data.table = tbl
				}
				result = payload
			case "vulnerabilities":
				tbl, payload := s.runVulnerabilities(ctx, tc.Function.Arguments, who)
				if tbl != nil {
					data.table = tbl
				}
				result = payload
			case "list_users":
				tbl, payload := s.runListUsers(ctx, tc.Function.Arguments, who)
				if tbl != nil {
					data.table = tbl
				}
				result = payload
			case "list_approvals":
				tbl, payload := s.runListApprovals(ctx, tc.Function.Arguments, who)
				if tbl != nil {
					data.table = tbl
				}
				result = payload
			case "windows_software":
				tbl, payload := s.runWindowsSoftware(ctx, tc.Function.Arguments, who)
				if tbl != nil {
					data.table = tbl
				}
				result = payload
			case "security_events":
				tbl, payload := s.runSecurityEvents(ctx, tc.Function.Arguments, who)
				if tbl != nil {
					data.table = tbl
				}
				result = payload
			case "platform_status":
				result = s.runPlatformStatus(ctx, who)
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
	// Ran out of tool iterations. The tool results are already in `messages`, so make
	// one final pass with tools DISABLED — the model must now WRITE an answer from what
	// it has instead of calling yet another tool. This turns a loop into a real answer.
	if resp, err := client.chat(ctx, chatRequest{Model: cfg.Model, Messages: messages, Options: deterministicOptions()}); err == nil {
		if final := strings.TrimSpace(resp.Message.Content); final != "" {
			s.remember(convoID, who.UserID, question, final)
			return final, data, nil
		}
	}
	final := "Here's what I found — see the details below."
	if data.table == nil && data.host == nil && data.history == nil && len(data.hosts) == 0 {
		final = "I couldn't fully resolve that from the data available to me."
	}
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
		Content: fmt.Sprintf("The %s tool was already run for this question and returned this data:\n%s",
			toolName, string(raw)),
	})
	// Same strong answer discipline as the LLM-loop refine pass (appended LAST).
	msgs = append(msgs, chatMessage{Role: "system", Content: scopeReminder})
	resp, err := client.chat(ctx, chatRequest{Model: cfg.Model, Messages: msgs, Options: deterministicOptions()})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(resp.Message.Content), nil
}

// scopeReminder is the short, focused answer-discipline instruction appended as the LAST
// message right before the final answer is generated. A late, concise reminder is obeyed
// by small models far more reliably than the same rules buried in the long system prompt
// — without it they enumerate every row and append recommendations. Used by BOTH the
// fast-path narration and the LLM-loop refine pass so every final answer is consistent.
const scopeReminder = "Now write the final answer to the user's question using ONLY the tool data " +
	"above. NEVER invent host names, counts, times, or values that are not in the data. Rules:\n" +
	"- Answer ONLY what was asked. If the question has a qualifier (failed, offline, critical, " +
	"pending, this/last week), include ONLY items matching it.\n" +
	"- For a \"which/list\" question (which hosts, which users, list X): NAME EVERY matching item with " +
	"its key value (e.g. each host with its disk-free %). Do not drop any or truncate to a few; if there " +
	"are many, give the count first, then still list them all.\n" +
	"- For a large EVENT/ACTIVITY log (dozens of similar rows — playbook runs, audit events): group " +
	"similar items and give counts (e.g. \"RouterOS Upgrade failed ~20 times, almost all on coreswitch\") " +
	"instead of enumerating each row.\n" +
	"- No recommendations, next steps, or \"you may want to…\" unless the user asked what to do.\n" +
	"- No preamble, no headings, no restating the question. Keep it tight.\n" +
	"- If the data is empty, say in one sentence that nothing matched — do NOT fill the gap with " +
	"related or invented data."

// refineFinalAnswer regenerates the final answer from the accumulated tool results with
// the scopeReminder appended as the LAST message. base already contains the system
// prompt, the question, and every tool result; tools are disabled so the model must WRITE
// an answer. Returns "" on failure so the caller keeps the model's original answer.
func (s *Service) refineFinalAnswer(ctx context.Context, client *ollamaClient, cfg Settings, base []chatMessage) string {
	msgs := append(append([]chatMessage(nil), base...), chatMessage{Role: "system", Content: scopeReminder})
	resp, err := client.chat(ctx, chatRequest{Model: cfg.Model, Messages: msgs, Options: deterministicOptions()})
	if err != nil {
		return ""
	}
	return strings.TrimSpace(resp.Message.Content)
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
	// The UI renders the raw host card; the model gets the host PLUS a disk breakdown
	// that pre-computes each mount's free% and names the mount driving the headline
	// "disk free %", so it can answer "which filesystem is that / where did 31% come
	// from" without doing arithmetic (which a small model gets wrong).
	payload := map[string]any{"host": host}
	if ds := diskFreeSummary(host.Metrics); ds != nil {
		payload["diskBreakdown"] = ds
	}
	return host, payload
}

// diskFreeSummary annotates a host's filesystems with the same numbers the fleet
// "disk free %" headline is built from. That headline is the MINIMUM of
// availBytes/sizeBytes across mounts (df Available / size). df's Available excludes
// filesystem-reserved blocks, so a mount's usedPct (used/size) and freePct
// (avail/size) do NOT sum to 100 — this makes that explicit so the assistant can
// explain the discrepancy instead of the user wondering where the number came from.
func diskFreeSummary(m *models.HostMetrics) map[string]any {
	if m == nil || len(m.Disk) == 0 {
		return nil
	}
	type fsRow struct {
		Mount     string  `json:"mount"`
		SizeBytes int64   `json:"sizeBytes"`
		UsedPct   float64 `json:"usedPct"` // used/size, as shown on the host card
		FreePct   float64 `json:"freePct"` // avail/size = what "disk free %" measures
	}
	rows := make([]fsRow, 0, len(m.Disk))
	tightest := ""
	minFree := 101.0
	for _, d := range m.Disk {
		if d.SizeBytes <= 0 {
			continue
		}
		free := float64(d.AvailBytes) / float64(d.SizeBytes) * 100
		rows = append(rows, fsRow{Mount: d.Mount, SizeBytes: d.SizeBytes, UsedPct: d.UsePct, FreePct: round1(free)})
		if free < minFree {
			minFree, tightest = free, d.Mount
		}
	}
	if len(rows) == 0 {
		return nil
	}
	return map[string]any{
		"filesystems":   rows,
		"tightestMount": tightest,
		"diskFreePct":   round1(minFree),
		"note": "The host's 'disk free %' (" + fmt.Sprintf("%.0f", minFree) + "%) is the free% of the tightest filesystem (" + tightest +
			"). free% is df Available / size; used% is used / size. They do not sum to 100 because df Available excludes filesystem-reserved blocks.",
	}
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
// runActivityFailures answers "any failed scans or playbook runs" by pulling both
// histories and returning ONLY the entries that actually FAILED (status), not the full
// history or scan compliance scores. This keeps the answer grounded and on-topic (the
// model otherwise reported scan pass/fail check counts and dropped the failed runs).
// diskFreeDirectAnswer builds the exact answer for a "which hosts have less/more than N%
// disk free" question from the already-filtered rows — count + EVERY matching host with
// its %. Returns "" if fargs isn't a disk-filter query. The store already applied the
// threshold, so every row matches.
func diskFreeDirectAnswer(question string, fargs json.RawMessage, rows []models.AssistantHostRow) string {
	var a queryHostsArgs
	_ = json.Unmarshal(fargs, &a)
	var threshold float64
	var dir string
	switch {
	case a.DiskFreePctMax != nil:
		threshold, dir = *a.DiskFreePctMax, "less"
	case a.DiskFreePctMin != nil:
		threshold, dir = *a.DiskFreePctMin, "more"
	default:
		return ""
	}
	thr := strconv.FormatFloat(threshold, 'f', -1, 64)
	if len(rows) == 0 {
		return fmt.Sprintf("No hosts have %s than %s%% disk free.", dir, thr)
	}
	sort.Slice(rows, func(i, j int) bool { return ptrF(rows[i].MinDiskFreePct) < ptrF(rows[j].MinDiskFreePct) })
	parts := make([]string, len(rows))
	for i, r := range rows {
		parts[i] = fmt.Sprintf("%s (%s%%)", r.Hostname, strconv.FormatFloat(ptrF(r.MinDiskFreePct), 'f', 1, 64))
	}
	noun := "hosts"
	if len(rows) == 1 {
		noun = "host"
	}
	return fmt.Sprintf("%d %s have %s than %s%% disk free: %s.", len(rows), noun, dir, thr, strings.Join(parts, ", "))
}

func ptrF(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

// calendarAdjustHours corrects a "today" session window from a 24h-rolling lookback to
// "since local midnight", so "who connected today" doesn't leak yesterday-evening
// sessions. Only touches session args with a "today" question and a non-"last" (Limit!=1)
// query; everything else passes through unchanged.
func (s *Service) calendarAdjustHours(ctx context.Context, question string, fargs json.RawMessage) json.RawMessage {
	if !strings.Contains(strings.ToLower(question), "today") {
		return fargs
	}
	var a sessionHistoryArgs
	if err := json.Unmarshal(fargs, &a); err != nil || a.Limit == 1 {
		return fargs
	}
	loc := s.displayLoc(ctx)
	now := time.Now().In(loc)
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	h := int(now.Sub(midnight).Hours()) // floor: window starts just after midnight, excludes yesterday
	if h < 1 {
		h = 1
	}
	a.Hours = h
	out, _ := json.Marshal(a)
	return out
}

// sessionDirectAnswer builds a concise answer for "who connected to <host>" questions:
// the single most recent for a "last connected" query (Limit==1), else distinct users
// with session counts — instead of the model dumping every session timestamp. Returns ""
// on empty so the narration handles the "no one connected" case.
func (s *Service) sessionDirectAnswer(ctx context.Context, fargs json.RawMessage, payload any) string {
	m, ok := payload.(map[string]any)
	if !ok {
		return ""
	}
	sessions, ok := m["sessions"].([]models.AssistantSSHSessionRow)
	if !ok || len(sessions) == 0 {
		return ""
	}
	var a sessionHistoryArgs
	_ = json.Unmarshal(fargs, &a)
	loc := s.displayLoc(ctx)
	when := func(t time.Time) string { return t.In(loc).Format("2006-01-02 15:04 MST") }

	if a.Limit == 1 { // "who last connected to <host>"
		r := sessions[0]
		return fmt.Sprintf("%s last connected to %s on %s.", r.Username, a.Hostname, when(r.StartedAt))
	}
	// "who connected to <host> [window]": distinct users with counts.
	counts := map[string]int{}
	order := []string{}
	for _, r := range sessions {
		if _, seen := counts[r.Username]; !seen {
			order = append(order, r.Username)
		}
		counts[r.Username]++
	}
	parts := make([]string, len(order))
	for i, u := range order {
		parts[i] = fmt.Sprintf("%s (%d session%s)", u, counts[u], plural(counts[u]))
	}
	return fmt.Sprintf("Connections to %s: %s.", a.Hostname, strings.Join(parts, ", "))
}

// metricTrendDirectAnswer builds a proper trend sentence from bucketed history — earliest
// vs latest value, direction, and range per metric — instead of letting the model narrate
// raw bucket fields (observed: "diskFreePctMin was 24.1 ... occurring once", raw floats).
func metricTrendDirectAnswer(hist *MetricHistory) string {
	if hist == nil || len(hist.Points) == 0 {
		return ""
	}
	pts := append([]store.MetricHistoryPoint(nil), hist.Points...)
	sort.Slice(pts, func(i, j int) bool { return pts[i].Time.Before(pts[j].Time) })
	metrics := hist.Metrics
	if len(metrics) == 0 {
		metrics = []string{"disk", "memory", "load"}
	}
	var clauses []string
	for _, mname := range metrics {
		var get func(store.MetricHistoryPoint) *float64
		var label, unit string
		switch mname {
		case "disk":
			get, label, unit = func(p store.MetricHistoryPoint) *float64 { return p.DiskFreePctAvg }, "disk-free", "%"
		case "memory":
			get, label, unit = func(p store.MetricHistoryPoint) *float64 { return p.MemUsedPctAvg }, "memory-used", "%"
		case "load":
			get, label, unit = func(p store.MetricHistoryPoint) *float64 { return p.LoadPerCoreAvg }, "load-per-core", ""
		default:
			continue
		}
		var first, last *float64
		mn, mx := math.Inf(1), math.Inf(-1)
		for _, p := range pts {
			v := get(p)
			if v == nil {
				continue
			}
			if first == nil {
				first = v
			}
			last = v
			mn, mx = math.Min(mn, *v), math.Max(mx, *v)
		}
		if first == nil {
			continue
		}
		dir := "held steady"
		if d := *last - *first; d <= -1 {
			dir = "fell"
		} else if d >= 1 {
			dir = "rose"
		}
		clauses = append(clauses, fmt.Sprintf("%s %s from %.1f%s to %.1f%s (min %.1f%s, max %.1f%s)",
			label, dir, *first, unit, *last, unit, mn, unit, mx, unit))
	}
	if len(clauses) == 0 {
		return ""
	}
	return fmt.Sprintf("On %s %s, %s.", hist.Hostname, windowPhrase(hist.WindowHours), strings.Join(clauses, "; "))
}

func windowPhrase(h int) string {
	switch {
	case h <= 24:
		return "over the past day"
	case h <= 49:
		return "over the past 2 days"
	case h <= 168:
		return "over the past week"
	case h <= 744:
		return "over the past month"
	default:
		return "recently"
	}
}

// auditChangesDirectAnswer builds a de-noised "what changed" summary from the audit tool's
// pre-computed changesByAction (operator changes), so the model can't re-introduce the
// routine automated noise (certificate issuance, assistant queries) or drop changes.
func auditChangesDirectAnswer(question string, payload any) string {
	m, ok := payload.(map[string]any)
	if !ok {
		return ""
	}
	changes, ok := m["changesByAction"].(map[string]int)
	if !ok {
		return ""
	}
	type kv struct {
		k string
		n int
	}
	var items []kv
	total := 0
	for k, n := range changes {
		items = append(items, kv{k, n})
		total += n
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].n != items[j].n {
			return items[i].n > items[j].n
		}
		return items[i].k < items[j].k
	})
	period := auditPeriodPhrase(strings.ToLower(question))
	if total == 0 {
		return "No operator changes were recorded in the audit log " + period + "."
	}
	// Cap to the top action types so a busy window doesn't produce a 40-item wall; the
	// full breakdown is in the table beneath.
	const topN = 8
	shown := items
	extra := 0
	if len(items) > topN {
		shown = items[:topN]
		extra = len(items) - topN
	}
	parts := make([]string, len(shown))
	for i, it := range shown {
		parts[i] = fmt.Sprintf("%d %s", it.n, it.k)
	}
	ans := fmt.Sprintf("%d change%s %s: %s", total, plural(total), period, strings.Join(parts, ", "))
	if extra > 0 {
		ans += fmt.Sprintf(", and %d other change type%s", extra, plural(extra))
	}
	ans += "."
	if routine, ok := m["routineByAction"].(map[string]int); ok {
		rc := 0
		for _, n := range routine {
			rc += n
		}
		if rc > 0 {
			ans += fmt.Sprintf(" (Plus %d routine automated events not shown.)", rc)
		}
	}
	return ans
}

func auditPeriodPhrase(lq string) string {
	switch {
	case strings.Contains(lq, "today"):
		return "today"
	case strings.Contains(lq, "yesterday"):
		return "yesterday"
	case strings.Contains(lq, "this week"), strings.Contains(lq, "past week"), strings.Contains(lq, "last week"):
		return "this week"
	case strings.Contains(lq, "month"):
		return "this month"
	default:
		return "recently"
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func (s *Service) runActivityFailures(ctx context.Context, who Caller) any {
	out := map[string]any{}
	if who.CanViewRuns || who.IsSuperAdmin {
		runs, err := s.store.RecentPlaybookRunsForAssistant(ctx, 100)
		if err == nil {
			failed := []models.AssistantPlaybookRunRow{}
			for _, r := range runs {
				if isFailedStatus(r.Status) {
					failed = append(failed, r)
				}
			}
			out["failedPlaybookRuns"] = failed
			out["failedPlaybookRunCount"] = len(failed)
		}
	}
	if who.CanViewScans || who.IsSuperAdmin {
		scans, err := s.store.RecentScansForAssistant(ctx, who.UserID, who.IsSuperAdmin, "", 100)
		if err == nil {
			// A "failed scan" is one that failed to RUN (status), not a completed scan
			// with a low compliance score — so filter by status, not pass/fail counts.
			failed := []models.AssistantScanRow{}
			for _, r := range scans {
				if isFailedStatus(r.Status) {
					failed = append(failed, r)
				}
			}
			out["failedScans"] = failed
			out["failedScanCount"] = len(failed)
		}
	}
	return out
}

func isFailedStatus(status string) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	return s == "failed" || s == "error" || s == "errored" || s == "failure"
}

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

// round1 rounds a non-negative percentage to one decimal place (no math import).
func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

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
	// Separate operator-initiated CHANGES from high-volume automated/background noise
	// (the assistant's own queries, per-session certificate issuance, KRL housekeeping).
	// Counts come from a window-wide aggregate (NOT the display-limited rows), so real
	// changes aren't crowded out of the summary by routine volume.
	changesByAction := map[string]int{}
	routineByAction := map[string]int{}
	changeCount := 0
	counts, cerr := s.store.AuditActionCountsForAssistant(ctx, windowSince(a.Hours, 24))
	if cerr != nil {
		counts = map[string]int{} // fall back to empty rather than fail the whole answer
	}
	for action, n := range counts {
		if isRoutineAuditAction(action) {
			routineByAction[action] += n
		} else {
			changesByAction[action] += n
			changeCount += n
		}
	}
	if len(rows) == 0 {
		tbl = nil
	}
	return tbl, map[string]any{
		"count": len(rows), "changeCount": changeCount,
		"changesByAction": changesByAction, "routineByAction": routineByAction,
		"events": rows,
	}
}

// isRoutineAuditAction reports whether an audit action is high-volume automated/background
// activity rather than an operator-initiated change — so a "what changed" summary can lead
// with real changes and treat these as background noise.
func isRoutineAuditAction(action string) bool {
	switch action {
	case "assistant.query", "certificate.issue", "certificate.renew", "certificate.revoke":
		return true
	}
	return strings.HasPrefix(action, "krl.")
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
	loc := s.displayLoc(ctx)
	rows := make([]models.AssistantScheduleRow, 0, len(scheds))
	for _, sc := range scheds {
		target := sc.TargetKind
		if sc.TargetName != "" {
			target += " " + sc.TargetName
		}
		rows = append(rows, models.AssistantScheduleRow{
			Name: sc.Name, Kind: sc.Kind, Enabled: sc.Enabled, Target: target,
			Recurrence: recurrenceSummary(sc.Recurrence, loc),
			// Present run times in the operator's display timezone so the model (and
			// the payload) report them in the operator's zone rather than UTC.
			LastRunAt: inLoc(sc.LastRunAt, loc), LastStatus: sc.LastStatus,
			NextRunAt: inLoc(sc.NextRunAt, loc), Running: sc.Running,
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

// displayLoc resolves the operator's configured display timezone, mirroring the
// scheduler's own fallback (server-local) so the assistant reports schedule times
// in the exact zone they actually fire in.
func (s *Service) displayLoc(ctx context.Context) *time.Location {
	if name := s.store.DisplayTimezone(ctx); name != "" {
		if loc, err := time.LoadLocation(name); err == nil {
			return loc
		}
	}
	return time.Local
}

// inLoc returns t shifted into loc (nil-safe), so a marshaled timestamp carries the
// display zone's offset rather than UTC's Z.
func inLoc(t *time.Time, loc *time.Location) *time.Time {
	if t == nil {
		return nil
	}
	v := t.In(loc)
	return &v
}

// recurrenceSummary renders a schedule's recurrence in words for the model/UI. For
// time-of-day recurrences it appends the display zone (e.g. "daily at 03:00 EDT"),
// since the time-of-day is interpreted in that zone — without the label the model
// tends to assume UTC.
func recurrenceSummary(r models.Recurrence, loc *time.Location) string {
	tz := ""
	if loc != nil {
		tz = " " + time.Now().In(loc).Format("MST")
	}
	switch r.Type {
	case "interval":
		if r.EveryMinutes > 0 && r.EveryMinutes%60 == 0 {
			return fmt.Sprintf("every %dh", r.EveryMinutes/60)
		}
		return fmt.Sprintf("every %dm", r.EveryMinutes)
	case "daily":
		return "daily at " + r.TimeOfDay + tz
	case "weekly":
		return "weekly on " + time.Weekday(r.Weekday).String() + " at " + r.TimeOfDay + tz
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
