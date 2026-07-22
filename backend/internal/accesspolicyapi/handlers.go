// Package accesspolicyapi is the management API for attribute-based access-control
// (ABAC) policies. Gated by AccessPolicy.Manage. The policies it manages are enforced
// at connect time by internal/accesspolicy.
package accesspolicyapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

// Mount attaches the access-policy routes, gated by AccessPolicy.Manage.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(d.Auth.RequirePermission("AccessPolicy.Manage"))
		pr.Get("/access-policies", h.list)
		pr.Post("/access-policies", h.create)
		pr.Put("/access-policies/{id}", h.update)
		pr.Delete("/access-policies/{id}", h.del)
	})
}

type handler struct{ d *app.Deps }

type policyReq struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Enabled      bool     `json:"enabled"`
	Priority     int      `json:"priority"`
	Environments []string `json:"environments"`
	Tags         []string `json:"tags"`
	Protocols    []string `json:"protocols"`
	ExemptRoles  []string `json:"exemptRoles"`
	ActiveDays   []int32  `json:"activeDays"`
	ActiveStart  int      `json:"activeStartMin"`
	ActiveEnd    int      `json:"activeEndMin"`
	DenyMessage  string   `json:"denyMessage"`
}

func (rq policyReq) validate() string {
	if strings.TrimSpace(rq.Name) == "" {
		return "name is required"
	}
	if rq.ActiveStart < 0 || rq.ActiveStart > 1439 || rq.ActiveEnd < 0 || rq.ActiveEnd > 1439 {
		return "active time must be minutes since midnight (0–1439)"
	}
	for _, d := range rq.ActiveDays {
		if d < 0 || d > 6 {
			return "active days must be 0 (Sunday) through 6 (Saturday)"
		}
	}
	for _, p := range rq.Protocols {
		if p != "ssh" && p != "rdp" {
			return "protocols must be ssh or rdp"
		}
	}
	return ""
}

func (rq policyReq) toInput(by uuid.UUID) store.AccessPolicyInput {
	return store.AccessPolicyInput{
		Name: strings.TrimSpace(rq.Name), Description: rq.Description, Enabled: rq.Enabled,
		Priority: rq.Priority, Environments: rq.Environments, Tags: rq.Tags, Protocols: rq.Protocols,
		ExemptRoles: rq.ExemptRoles, ActiveDays: rq.ActiveDays, ActiveStart: rq.ActiveStart,
		ActiveEnd: rq.ActiveEnd, DenyMessage: rq.DenyMessage, CreatedBy: by,
	}
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	pols, err := h.d.Store.ListAccessPolicies(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list policies")
		return
	}
	if pols == nil {
		pols = []store.AccessPolicy{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"policies": pols})
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var rq policyReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if msg := rq.validate(); msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	p := auth.MustPrincipal(r)
	pol, err := h.d.Store.CreateAccessPolicy(r.Context(), rq.toInput(p.UserID))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create policy")
		return
	}
	h.audit(r, "access_policy.create", pol.ID, map[string]any{"name": pol.Name, "enabled": pol.Enabled})
	httpx.WriteJSON(w, http.StatusCreated, pol)
}

func (h *handler) update(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var rq policyReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if msg := rq.validate(); msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	p := auth.MustPrincipal(r)
	pol, err := h.d.Store.UpdateAccessPolicy(r.Context(), id, rq.toInput(p.UserID))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update policy")
		return
	}
	h.audit(r, "access_policy.update", pol.ID, map[string]any{"name": pol.Name, "enabled": pol.Enabled})
	httpx.WriteJSON(w, http.StatusOK, pol)
}

func (h *handler) del(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := h.d.Store.DeleteAccessPolicy(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete policy")
		return
	}
	h.audit(r, "access_policy.delete", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) audit(r *http.Request, action string, id uuid.UUID, detail map[string]any) {
	p := auth.MustPrincipal(r)
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: action,
		TargetKind: "access_policy", TargetID: id.String(), Detail: detail,
		IP: clientIP(r),
	})
}

func parseID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return uuid.Nil, false
	}
	return id, true
}

// clientIP extracts the request IP (best-effort; the reverse proxy sets X-Forwarded-For).
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host
}
