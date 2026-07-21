// Package tenantapi is the provider-admin API for managing customer tenants in
// multi-tenant (MSP) mode. Every route requires the caller to be a provider-tenant
// admin (Tenant.Manage in the provider tenant), and runs cross-tenant with RLS bypassed.
package tenantapi

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/tenant"
)

// Mount attaches the tenant-management routes.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(h.gate)
		pr.Get("/tenants", h.list)
		pr.Post("/tenants", h.create)
		pr.Get("/tenants/{id}", h.get)
		pr.Patch("/tenants/{id}", h.rename)
		pr.Post("/tenants/{id}/status", h.setStatus)
	})
}

type handler struct{ d *app.Deps }

// gate requires multi-tenancy to be enabled AND the caller to be a provider admin.
func (h *handler) gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.d.Cfg.MultiTenancy {
			httpx.WriteError(w, http.StatusBadRequest, "multi-tenancy is not enabled (set FLEET_MULTI_TENANCY=true)")
			return
		}
		if p := auth.MustPrincipal(r); p == nil || !p.IsProviderAdmin() {
			httpx.WriteError(w, http.StatusForbidden, "provider-tenant admin required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	ts, err := h.d.Store.ListTenants(tenant.WithBypass(r.Context()))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list tenants")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"tenants": ts})
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	t, err := h.d.Store.CreateTenant(tenant.WithBypass(r.Context()), req.Name)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "tenant.create", t.ID, map[string]any{"name": t.Name, "slug": t.Slug})
	httpx.WriteJSON(w, http.StatusCreated, t)
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid tenant id")
		return
	}
	t, err := h.d.Store.GetTenant(tenant.WithBypass(r.Context()), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "tenant not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

func (h *handler) rename(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid tenant id")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := h.d.Store.RenameTenant(tenant.WithBypass(r.Context()), id, req.Name); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "tenant.rename", id, map[string]any{"name": req.Name})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *handler) setStatus(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid tenant id")
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := h.d.Store.SetTenantStatus(tenant.WithBypass(r.Context()), id, req.Status); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "tenant.set_status", id, map[string]any{"status": req.Status})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *handler) audit(r *http.Request, action string, tenantID uuid.UUID, detail map[string]any) {
	p := auth.MustPrincipal(r)
	var actor *uuid.UUID
	name := ""
	if p != nil {
		actor = &p.UserID
		name = p.Username
	}
	_, _ = h.d.Store.AppendAudit(tenant.WithBypass(r.Context()), models.AuditEvent{
		ActorID: actor, ActorName: name, Action: action,
		TargetKind: "tenant", TargetID: tenantID.String(), Detail: detail,
	})
}
