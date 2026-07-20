// Package commandpolicyapi manages command-control rules and approves gated
// commands. Everything here is gated by CommandPolicy.Manage. Enforcement of the
// rules happens in the terminal relay (see internal/commandpolicy).
package commandpolicyapi

import (
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/store"
)

// waiverTTL is how long an approved command waiver stays valid — long enough to
// re-run the command, short enough that approval isn't a standing grant.
const waiverTTL = 10 * time.Minute

// Mount attaches command-policy routes, gated by CommandPolicy.Manage.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(d.Auth.RequirePermission("CommandPolicy.Manage"))
		pr.Get("/command-policies", h.list)
		pr.Post("/command-policies", h.create)
		pr.Put("/command-policies/{id}", h.update)
		pr.Delete("/command-policies/{id}", h.remove)
		pr.Get("/command-approvals", h.listApprovals)
		pr.Post("/command-approvals/{id}/approve", h.approve)
		pr.Post("/command-approvals/{id}/deny", h.deny)
	})
}

type handler struct{ d *app.Deps }

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	rules, err := h.d.Store.ListCommandPolicies(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list rules")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

type ruleReq struct {
	Name         string  `json:"name"`
	Pattern      string  `json:"pattern"`
	Action       string  `json:"action"`
	ScopeKind    string  `json:"scopeKind"`
	ScopeGroupID *string `json:"scopeGroupId"`
	Enabled      *bool   `json:"enabled"`
}

// validate normalizes and checks a rule request, returning the store input and an
// error message ("" if valid).
func (rq *ruleReq) validate() (store.CommandPolicyInput, string) {
	in := store.CommandPolicyInput{
		Name: rq.Name, Pattern: rq.Pattern, Action: rq.Action, ScopeKind: rq.ScopeKind, Enabled: true,
	}
	if rq.Enabled != nil {
		in.Enabled = *rq.Enabled
	}
	if in.Name == "" {
		return in, "name is required"
	}
	if in.Pattern == "" {
		return in, "pattern is required"
	}
	if _, err := regexp.Compile(in.Pattern); err != nil {
		return in, "invalid regular expression: " + err.Error()
	}
	switch in.Action {
	case "flag", "block", "approval":
	default:
		return in, "action must be flag, block, or approval"
	}
	switch in.ScopeKind {
	case "global":
		in.ScopeGroupID = nil
	case "group":
		if rq.ScopeGroupID == nil || *rq.ScopeGroupID == "" {
			return in, "a group is required for group scope"
		}
		gid, err := uuid.Parse(*rq.ScopeGroupID)
		if err != nil {
			return in, "invalid group id"
		}
		in.ScopeGroupID = &gid
	default:
		return in, "scope must be global or group"
	}
	return in, ""
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var rq ruleReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	in, msg := rq.validate()
	if msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	p := auth.MustPrincipal(r)
	id, err := h.d.Store.CreateCommandPolicy(r.Context(), in, p.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create rule")
		return
	}
	h.audit(r, "command_policy.create", id.String(), map[string]any{"name": in.Name, "action": in.Action})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (h *handler) update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var rq ruleReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	in, msg := rq.validate()
	if msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	if err := h.d.Store.UpdateCommandPolicy(r.Context(), id, in); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update rule")
		return
	}
	h.audit(r, "command_policy.update", id.String(), map[string]any{"name": in.Name, "action": in.Action})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *handler) remove(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.d.Store.DeleteCommandPolicy(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete rule")
		return
	}
	h.audit(r, "command_policy.delete", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *handler) listApprovals(w http.ResponseWriter, r *http.Request) {
	items, err := h.d.Store.ListPendingCommandApprovals(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list approvals")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"approvals": items})
}

func (h *handler) approve(w http.ResponseWriter, r *http.Request) { h.decide(w, r, true) }
func (h *handler) deny(w http.ResponseWriter, r *http.Request)    { h.decide(w, r, false) }

func (h *handler) decide(w http.ResponseWriter, r *http.Request, approve bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	p := auth.MustPrincipal(r)
	ok, err := h.d.Store.DecideCommandApproval(r.Context(), id, p.UserID, approve, waiverTTL)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not record decision")
		return
	}
	if !ok {
		// Either already decided, or the approver is the requester (separation of duties).
		httpx.WriteError(w, http.StatusConflict, "request is not pending, or you cannot approve your own request")
		return
	}
	action := "command_policy.deny"
	if approve {
		action = "command_policy.approve"
	}
	h.audit(r, action, id.String(), nil)
	if h.d.Notify != nil {
		verb := "denied"
		if approve {
			verb = "approved"
		}
		h.d.Notify.Notify(r.Context(), notify.Event{
			Type: notify.EventCommandApproval, Severity: notify.SeverityInfo,
			Title: "Command approval " + verb, Body: "A gated-command request was " + verb + ".",
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *handler) audit(r *http.Request, action, targetID string, detail map[string]any) {
	p := auth.MustPrincipal(r)
	if p == nil {
		return
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: action,
		TargetKind: "command_policy", TargetID: targetID, Detail: detail,
	})
}
