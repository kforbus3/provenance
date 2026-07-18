package admin

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
)

func (h *handler) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := h.d.Store.ListGroups(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list groups")
		return
	}
	if groups == nil {
		groups = []models.Group{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"groups": groups, "count": len(groups)})
}

type createGroupReq struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Rule        *models.GroupRule `json:"rule"` // non-empty = dynamic membership
}

func (h *handler) createGroup(w http.ResponseWriter, r *http.Request) {
	var rq createGroupReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil || rq.Name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	group, err := h.d.Store.CreateGroup(r.Context(), rq.Name, rq.Description)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create group")
		return
	}
	if !rq.Rule.Empty() {
		if err := h.d.Store.SetGroupRule(r.Context(), group.ID, rq.Rule); err == nil {
			_, _ = h.d.Store.RecomputeGroup(r.Context(), group.ID)
			group.Rule = rq.Rule
		}
	}
	h.audit(r, "group.create", "group", group.ID.String(), map[string]any{"name": group.Name, "dynamic": !rq.Rule.Empty()})
	httpx.WriteJSON(w, http.StatusCreated, group)
}

// updateGroup edits a group's dynamic membership rule (setting or clearing it),
// then recomputes membership. Manual host membership is managed elsewhere and is
// disabled while a rule is set.
func (h *handler) updateGroup(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid group id")
		return
	}
	var rq struct {
		Rule *models.GroupRule `json:"rule"`
	}
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.d.Store.SetGroupRule(r.Context(), id, rq.Rule); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update group rule")
		return
	}
	count, _ := h.d.Store.RecomputeGroup(r.Context(), id)
	h.audit(r, "group.update", "group", id.String(), map[string]any{"dynamic": !rq.Rule.Empty(), "members": count})
	g, err := h.d.Store.GetGroup(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such group")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, g)
}

func (h *handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid group id")
		return
	}
	if err := h.d.Store.DeleteGroup(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete group")
		return
	}
	h.audit(r, "group.delete", "group", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
