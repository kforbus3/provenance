package assistant

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
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
	writeJSON(w, http.StatusOK, h.svc.Status(r.Context()))
}

func (h *handler) models(w http.ResponseWriter, r *http.Request) {
	list, err := h.svc.Models(r.Context(), r.URL.Query().Get("url"))
	if err != nil {
		writeError(w, http.StatusBadGateway, "could not reach Ollama: "+err.Error())
		return
	}
	if list == nil {
		list = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": list})
}

type askReq struct {
	Question string `json:"question"`
}

func (h *handler) ask(w http.ResponseWriter, r *http.Request) {
	var rq askReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil || len(rq.Question) == 0 {
		writeError(w, http.StatusBadRequest, "question is required")
		return
	}
	if len(rq.Question) > 2000 {
		rq.Question = rq.Question[:2000]
	}
	p := auth.MustPrincipal(r)
	id, ok := h.svc.Ask(r.Context(), rq.Question, Caller{
		UserID: p.UserID, IsSuperAdmin: p.IsSuperAdmin, Username: p.Username,
		CanViewSessions: p.Has("Session.Replay"),
	})
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "assistant is not enabled")
		return
	}
	h.audit(r, "assistant.query", map[string]any{"question": rq.Question})
	writeJSON(w, http.StatusAccepted, map[string]any{"id": id})
}

func (h *handler) result(w http.ResponseWriter, r *http.Request) {
	res, ok := h.svc.Result(chi.URLParam(r, "id"))
	if !ok {
		writeError(w, http.StatusNotFound, "no such request")
		return
	}
	writeJSON(w, http.StatusOK, res)
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
