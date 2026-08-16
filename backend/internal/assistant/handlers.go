package assistant

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kforbus3/Moorgate/backend/internal/app"
	"github.com/kforbus3/Moorgate/backend/internal/auth"
	"github.com/kforbus3/Moorgate/backend/internal/httpx"
	"github.com/kforbus3/Moorgate/backend/internal/models"
)

// Mount attaches assistant routes, gated by auth + permissions.
func Mount(r chi.Router, d *app.Deps, svc *Service) {
	h := &handler{d: d, svc: svc}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("Assistant.Use")).Get("/assistant/status", h.status)
		pr.With(d.Auth.RequirePermission("System.Configure")).Get("/assistant/models", h.models)
		pr.With(d.Auth.RequirePermission("Assistant.Use")).Post("/assistant/ask", h.ask)
		pr.With(d.Auth.RequirePermission("Assistant.Use")).Get("/assistant/ask/{id}", h.result)
		pr.With(d.Auth.RequirePermission("Assistant.Use")).Post("/assistant/feedback", h.feedback)
	})
}

type handler struct {
	d   *app.Deps
	svc *Service
}

func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.svc.Status(r.Context()))
}

func (h *handler) models(w http.ResponseWriter, r *http.Request) {
	list, err := h.svc.Models(r.Context(), r.URL.Query().Get("url"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "could not reach Ollama at that URL")
		return
	}
	if list == nil {
		list = []string{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"models": list})
}

type askReq struct {
	Question       string `json:"question"`
	ConversationID string `json:"conversationId"`
}

func (h *handler) ask(w http.ResponseWriter, r *http.Request) {
	var rq askReq
	// Cap the body so a giant "question" can't exhaust memory (the 2000-char clamp
	// below runs only after a full decode).
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&rq); err != nil || len(rq.Question) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "question is required")
		return
	}
	if len(rq.Question) > 2000 {
		rq.Question = rq.Question[:2000]
	}
	p := auth.MustPrincipal(r)
	id, convoID, ok := h.svc.Ask(r.Context(), rq.Question, rq.ConversationID, Caller{
		UserID: p.UserID, IsSuperAdmin: p.IsSuperAdmin, Username: p.Username,
		CanViewSessions:   p.Has("Session.Replay"),
		CanViewScans:      p.Has("Host.Scan"),
		CanViewRuns:       p.Has("Playbook.Run"),
		CanViewAudit:      p.Has("Audit.View"),
		CanViewSchedules:  p.Has("Schedule.Manage"),
		CanViewTransfers:  p.Has("File.Transfer"),
		CanViewCommands:   p.Has("Command.Run"),
		CanViewUsers:      p.Has("User.Edit"),
		CanViewApprovals:  p.Has("Approval.Request") || p.Has("Approval.Decide"),
		CanViewCluster:    p.Has("System.Configure"),
		CanViewEnrollment: p.Has("Host.Enroll"),
		CanAct:            p.Has("Assistant.Act"),
		Perms:             p.Permissions,
	})
	if !ok {
		httpx.WriteError(w, http.StatusServiceUnavailable, "assistant is not enabled")
		return
	}
	h.audit(r, "assistant.query", map[string]any{"question": rq.Question})
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"id": id, "conversationId": convoID})
}

func (h *handler) result(w http.ResponseWriter, r *http.Request) {
	res, ok := h.svc.Result(chi.URLParam(r, "id"), auth.MustPrincipal(r).UserID)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "no such request")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

type feedbackReq struct {
	AskID      string `json:"askId"`
	Question   string `json:"question"`
	Answer     string `json:"answer"`
	AnsweredBy string `json:"answeredBy"`
	Helpful    *bool  `json:"helpful"`
	Comment    string `json:"comment"`
}

// feedback records a thumbs up/down on an answer. The client echoes the question/answer/
// tool back (results are one-shot server-side), so the row is self-contained telemetry
// from the authenticated user.
func (h *handler) feedback(w http.ResponseWriter, r *http.Request) {
	var rq feedbackReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&rq); err != nil || rq.Helpful == nil || rq.Question == "" {
		httpx.WriteError(w, http.StatusBadRequest, "helpful and question are required")
		return
	}
	clamp := func(s string, n int) string {
		if len(s) > n {
			return s[:n]
		}
		return s
	}
	p := auth.MustPrincipal(r)
	err := h.d.Store.RecordAssistantFeedback(r.Context(), p.UserID, clamp(rq.AskID, 64),
		clamp(rq.Question, 2000), clamp(rq.Answer, 8000), clamp(rq.AnsweredBy, 64),
		*rq.Helpful, clamp(rq.Comment, 2000))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not record feedback")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *handler) audit(r *http.Request, action string, detail map[string]any) {
	p := auth.MustPrincipal(r)
	var actorID *uuid.UUID
	var name string
	if p != nil {
		actorID = &p.UserID
		name = p.Username
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: actorID, ActorName: name, Action: action, TargetKind: "assistant", Detail: detail,
	})
}
