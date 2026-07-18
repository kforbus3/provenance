package aiaction

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
)

type handler struct {
	d   *app.Deps
	reg *Registry
}

// Mount registers the assistant-action confirmation surface. Every route requires
// Assistant.Act on top of the per-action permission re-checked at execution.
func Mount(r chi.Router, d *app.Deps, reg *Registry) {
	h := &handler{d: d, reg: reg}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(d.Auth.RequirePermission("Assistant.Act"))
		pr.Get("/assistant/actions", h.list)
		pr.Post("/assistant/actions/{id}/execute", h.execute)
		pr.Post("/assistant/actions/{id}/cancel", h.cancel)
	})
}

func actorFrom(p *auth.Principal) Actor {
	return Actor{UserID: p.UserID, Username: p.Username, IsSuper: p.IsSuperAdmin, Can: p.Has}
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	actions, err := h.reg.List(r.Context(), actorFrom(auth.MustPrincipal(r)), 50)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list actions")
		return
	}
	if actions == nil {
		actions = []models.AssistantAction{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

func (h *handler) execute(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid action id")
		return
	}
	action, err := h.reg.Execute(r.Context(), actorFrom(auth.MustPrincipal(r)), id)
	// When the action ran (executed or failed) we return its record so the UI can
	// show the outcome; only pre-execution errors become error responses.
	if action != nil {
		httpx.WriteJSON(w, http.StatusOK, action)
		return
	}
	writeActionErr(w, err)
}

func (h *handler) cancel(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid action id")
		return
	}
	if err := h.reg.Cancel(r.Context(), actorFrom(auth.MustPrincipal(r)), id); err != nil {
		writeActionErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"cancelled": true})
}

func writeActionErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "action not found")
	case errors.Is(err, ErrExpired), errors.Is(err, ErrNotPending):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	default:
		var pe *PermError
		if errors.As(err, &pe) {
			httpx.WriteError(w, http.StatusForbidden, "you don't have permission ("+pe.Permission+")")
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	}
}
