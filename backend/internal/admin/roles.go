package admin

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
)

func (h *handler) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.d.Store.ListRoles(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list roles")
		return
	}
	if roles == nil {
		roles = []models.Role{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"roles": roles, "count": len(roles)})
}

type createRoleReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (h *handler) createRole(w http.ResponseWriter, r *http.Request) {
	var rq createRoleReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil || rq.Name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	role, err := h.d.Store.CreateRole(r.Context(), rq.Name, rq.Description)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create role")
		return
	}
	h.audit(r, "role.create", "role", role.ID.String(), map[string]any{"name": role.Name})
	httpx.WriteJSON(w, http.StatusCreated, role)
}

func (h *handler) deleteRole(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid role id")
		return
	}
	if err := h.d.Store.DeleteRole(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete role")
		return
	}
	h.audit(r, "role.delete", "role", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

type setRolePermsReq struct {
	Permissions []string `json:"permissions"`
}

func (h *handler) setRolePermissions(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid role id")
		return
	}
	var rq setRolePermsReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if rq.Permissions == nil {
		rq.Permissions = []string{}
	}
	if err := h.d.Store.SetRolePermissions(r.Context(), id, rq.Permissions); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not set permissions")
		return
	}
	h.audit(r, "role.set_permissions", "role", id.String(), map[string]any{"permissions": rq.Permissions})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *handler) listPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := h.d.Store.ListPermissions(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list permissions")
		return
	}
	if perms == nil {
		perms = []models.Permission{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"permissions": perms, "count": len(perms)})
}
