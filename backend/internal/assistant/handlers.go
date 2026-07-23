package assistant

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
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
