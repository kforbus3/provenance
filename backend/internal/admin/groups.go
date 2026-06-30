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
	Name        string `json:"name"`
	Description string `json:"description"`
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
	h.audit(r, "group.create", "group", group.ID.String(), map[string]any{"name": group.Name})
	httpx.WriteJSON(w, http.StatusCreated, group)
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
