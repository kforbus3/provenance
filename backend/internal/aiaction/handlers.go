package aiaction

import (
	"encoding/json"
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

// Mount registers the assistant-action surface: the requester routes (Assistant.Act)
// and the approver routes (Assistant.Approve). Every mutation re-checks the
// per-action permission at execution.
func Mount(r chi.Router, d *app.Deps, reg *Registry) {
	h := &handler{d: d, reg: reg}
	// Requester surface.
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(d.Auth.RequirePermission("Assistant.Act"))
		pr.Get("/assistant/actions", h.list)
		pr.Post("/assistant/actions/{id}/execute", h.execute)                  // safe actions run here
		pr.Post("/assistant/actions/{id}/request-approval", h.requestApproval) // guarded actions route here
		pr.Post("/assistant/actions/{id}/cancel", h.cancel)
	})
	// Approver surface (second person; separation of duties enforced in the registry).
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(d.Auth.RequirePermission("Assistant.Approve"))
		pr.Get("/assistant/actions/approvals", h.listApprovals)
		pr.Post("/assistant/actions/{id}/approve", h.approve)
		pr.Post("/assistant/actions/{id}/deny", h.deny)
	})
	// Admin policy for assistant actions.
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(d.Auth.RequirePermission("System.Configure"))
		pr.Get("/assistant/actions/policy", h.getPolicy)
		pr.Put("/assistant/actions/policy", h.setPolicy)
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

func (h *handler) requestApproval(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid action id")
		return
	}
	action, err := h.reg.RequestApproval(r.Context(), actorFrom(auth.MustPrincipal(r)), id)
	if err != nil {
		writeActionErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, action)
}

func (h *handler) listApprovals(w http.ResponseWriter, r *http.Request) {
	actions, err := h.reg.ListApprovals(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list approvals")
		return
	}
	if actions == nil {
		actions = []models.AssistantAction{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

func (h *handler) approve(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid action id")
		return
	}
	action, err := h.reg.Approve(r.Context(), actorFrom(auth.MustPrincipal(r)), id)
	if action != nil { // executed or failed — return the record so the UI shows the outcome
		httpx.WriteJSON(w, http.StatusOK, action)
		return
	}
	writeActionErr(w, err)
}

func (h *handler) deny(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid action id")
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
	action, err := h.reg.Deny(r.Context(), actorFrom(auth.MustPrincipal(r)), id, body.Note)
	if err != nil {
		writeActionErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, action)
}

func (h *handler) getPolicy(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"policy":  h.reg.Policy(r.Context()),
		"actions": h.reg.Kinds(),
	})
}

func (h *handler) setPolicy(w http.ResponseWriter, r *http.Request) {
	var p Policy
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&p); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.reg.SavePolicy(r.Context(), p); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save policy")
		return
	}
	if pr := auth.MustPrincipal(r); pr != nil {
		_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
			ActorID: &pr.UserID, ActorName: pr.Username, Action: "system.assistant_action_policy", TargetKind: "system",
			Detail: map[string]any{"requireApprovalForAll": p.RequireApprovalForAll, "disabledKinds": p.DisabledKinds},
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"saved": true})
}

func writeActionErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "action not found")
	case errors.Is(err, ErrExpired), errors.Is(err, ErrNotPending), errors.Is(err, ErrRequiresApproval):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrSelfApproval):
		httpx.WriteError(w, http.StatusForbidden, err.Error())
	default:
		var pe *PermError
		if errors.As(err, &pe) {
			httpx.WriteError(w, http.StatusForbidden, "you don't have permission ("+pe.Permission+")")
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	}
}
