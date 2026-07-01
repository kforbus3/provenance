// Package approvals implements the just-in-time access workflow: users request
// time-boxed access to a host or group, approvers decide, and approved requests
// mint temporary_permissions grants that expire automatically.
package approvals

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

// Mount attaches approval routes to r, gated by authentication and permissions.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)

		pr.With(d.Auth.RequirePermission("Approval.Request")).Post("/approvals", h.create)
		pr.With(d.Auth.RequirePermission("Approval.Request")).Get("/approvals/targets", h.targets)
		pr.With(d.Auth.RequirePermission("Approval.Request")).Get("/approvals", h.list)
		pr.With(d.Auth.RequirePermission("Approval.Request")).Get("/approvals/mine", h.listMine)
		pr.With(d.Auth.RequirePermission("Approval.Request")).Get("/approvals/grants/mine", h.grantsMine)
		pr.With(d.Auth.RequirePermission("Approval.Decide")).Post("/approvals/{id}/decide", h.decide)
	})
}

type handler struct{ d *app.Deps }

type approvalReq struct {
	Reason        string `json:"reason"`
	TargetKind    string `json:"targetKind"`
	HostID        string `json:"hostId"`
	GroupID       string `json:"groupId"`
	RequestedSecs int64  `json:"requestedSecs"`
	TicketRef     string `json:"ticketRef"`
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	var rq approvalReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if rq.RequestedSecs <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "requestedSecs must be positive")
		return
	}
	in := store.ApprovalRequestInput{
		RequesterID:   p.UserID,
		TargetKind:    rq.TargetKind,
		Reason:        rq.Reason,
		TicketRef:     rq.TicketRef,
		RequestedSecs: rq.RequestedSecs,
	}
	switch rq.TargetKind {
	case "host":
		id, err := uuid.Parse(rq.HostID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "valid hostId is required")
			return
		}
		in.HostID = &id
	case "group":
		id, err := uuid.Parse(rq.GroupID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "valid groupId is required")
			return
		}
		in.GroupID = &id
	default:
		httpx.WriteError(w, http.StatusBadRequest, "targetKind must be host or group")
		return
	}
	ar, err := h.d.Store.CreateApprovalRequest(r.Context(), in)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create approval request")
		return
	}
	h.audit(r, "approval.request", ar.ID.String(), map[string]any{
		"targetKind": ar.TargetKind, "targetName": ar.TargetName, "requestedSecs": ar.RequestedSecs,
	})
	if h.d.Notify != nil {
		p := auth.MustPrincipal(r)
		h.d.Notify.Notify(r.Context(), notify.Event{
			Type: notify.EventApprovalPending, Severity: notify.SeverityInfo,
			Title: "Access request pending approval",
			Body: fmt.Sprintf("%s requested access to %s %q. Review it in Approvals → Queue.",
				p.Username, ar.TargetKind, ar.TargetName),
		})
	}
	httpx.WriteJSON(w, http.StatusCreated, ar)
}

// requestTarget is a host or group a requester can pick when filing an access
// request, by name rather than raw UUID.
type requestTarget struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Environment string `json:"environment,omitempty"`
}

// targets serves the access-request name picker: a server-side search over hosts
// or groups (?kind=host|group&q=...), capped server-side so it scales to large
// fleets. Targets the requester can already reach are excluded — there is
// nothing to request for those. (A super admin reaches everything, so their
// picker is intentionally empty; requests come from users who lack access.)
//
// We over-fetch from the search and stop once `limit` un-reached targets are
// collected, so excluding a user's accessible matches doesn't shrink the list.
func (h *handler) targets(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	ctx := r.Context()
	q := r.URL.Query().Get("q")
	const limit = 50

	out := make([]requestTarget, 0, limit)
	switch r.URL.Query().Get("kind") {
	case "", "host":
		hosts, err := h.d.Store.SearchHosts(ctx, q, limit*2)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not search hosts")
			return
		}
		have, err := h.d.Store.AccessibleHostIDs(ctx, p.UserID, p.IsSuperAdmin)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not load access")
			return
		}
		for _, hh := range hosts {
			if have[hh.ID] {
				continue
			}
			out = append(out, requestTarget{ID: hh.ID.String(), Name: hh.Hostname, Environment: hh.Environment})
			if len(out) >= limit {
				break
			}
		}
	case "group":
		groups, err := h.d.Store.SearchGroups(ctx, q, limit*2)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not search groups")
			return
		}
		have, err := h.d.Store.AccessibleGroupIDs(ctx, p.UserID, p.IsSuperAdmin)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not load access")
			return
		}
		for _, g := range groups {
			if have[g.ID] {
				continue
			}
			out = append(out, requestTarget{ID: g.ID.String(), Name: g.Name})
			if len(out) >= limit {
				break
			}
		}
	default:
		httpx.WriteError(w, http.StatusBadRequest, "kind must be host or group")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"targets": out})
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	status := r.URL.Query().Get("status")
	var requester *uuid.UUID
	// Deciders see every request; requesters only see their own.
	if !p.Has("Approval.Decide") {
		requester = &p.UserID
	}
	reqs, err := h.d.Store.ListApprovalRequests(r.Context(), status, requester)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list approval requests")
		return
	}
	if reqs == nil {
		reqs = []models.ApprovalRequest{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"approvals": reqs, "count": len(reqs)})
}

func (h *handler) listMine(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	status := r.URL.Query().Get("status")
	reqs, err := h.d.Store.ListApprovalRequests(r.Context(), status, &p.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list approval requests")
		return
	}
	if reqs == nil {
		reqs = []models.ApprovalRequest{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"approvals": reqs, "count": len(reqs)})
}

func (h *handler) grantsMine(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	grants, err := h.d.Store.ListTemporaryPermissions(r.Context(), p.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list grants")
		return
	}
	if grants == nil {
		grants = []models.TemporaryPermission{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"grants": grants, "count": len(grants)})
}

type decideReq struct {
	Decision    string `json:"decision"` // approve|deny
	Note        string `json:"note"`
	GrantedSecs int64  `json:"grantedSecs"`
}

func (h *handler) decide(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid approval id")
		return
	}
	var rq decideReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var status string
	switch rq.Decision {
	case "approve", "approved":
		status = "approved"
	case "deny", "denied":
		status = "denied"
	default:
		httpx.WriteError(w, http.StatusBadRequest, "decision must be approve or deny")
		return
	}
	existing, err := h.d.Store.GetApprovalRequest(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "approval request not found")
		return
	}
	if existing.Status != "pending" {
		httpx.WriteError(w, http.StatusConflict, "approval request is not pending")
		return
	}
	grantedSecs := rq.GrantedSecs
	if status == "approved" && grantedSecs <= 0 {
		grantedSecs = existing.RequestedSecs
	}
	p := auth.MustPrincipal(r)
	ar, err := h.d.Store.DecideApprovalRequest(r.Context(), id, p.UserID, status, rq.Note, grantedSecs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not record decision")
		return
	}
	h.audit(r, "approval.decide", ar.ID.String(), map[string]any{
		"status": ar.Status, "grantedSecs": grantedSecs, "note": rq.Note,
	})
	// Notify that the request is resolved: the admin distribution/webhook (per the
	// event's route) and the requester directly at their profile email, if set.
	if h.d.Notify != nil {
		body := fmt.Sprintf("Your access request for %s %q was %s by %s.",
			ar.TargetKind, ar.TargetName, ar.Status, p.Username)
		if ar.Status == "approved" && ar.GrantedSecs != nil {
			body += fmt.Sprintf(" Access is granted for %s.", (time.Duration(*ar.GrantedSecs) * time.Second).String())
		}
		if ar.DecisionNote != "" {
			body += " Note: " + ar.DecisionNote
		}
		var recipient string
		if u, err := h.d.Store.GetUserByID(r.Context(), ar.RequesterID); err == nil {
			recipient = u.Email
		}
		h.d.Notify.Notify(r.Context(), notify.Event{
			Type: notify.EventApprovalResolved, Severity: notify.SeverityInfo,
			Title:     "Access request " + ar.Status,
			Body:      body,
			Recipient: recipient,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, ar)
}

func (h *handler) audit(r *http.Request, action, targetID string, detail map[string]any) {
	p := auth.MustPrincipal(r)
	var actorID *uuid.UUID
	var name string
	if p != nil {
		actorID = &p.UserID
		name = p.Username
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: actorID, ActorName: name, Action: action,
		TargetKind: "approval", TargetID: targetID, Detail: detail,
	})
}

// Reaper expires due temporary_permissions in a single pass and notifies each
// affected user that their just-in-time access has ended. The main server
// schedules this on an interval.
func Reaper(ctx context.Context, d *app.Deps) {
	grants, err := d.Store.ExpireTemporaryPermissions(ctx)
	if err != nil {
		d.Log.Error("approval grant reaper failed", "error", err)
		return
	}
	if len(grants) == 0 {
		return
	}
	d.Log.Info("expired temporary permissions", "count", len(grants))
	if d.Notify == nil {
		return
	}
	for _, g := range grants {
		d.Notify.Notify(ctx, notify.Event{
			Type: notify.EventAccessExpired, Severity: notify.SeverityInfo,
			Title: "Just-in-time access expired",
			Body: fmt.Sprintf("Temporary access to %s %q for %s has expired.",
				g.TargetKind, g.TargetName, g.Username),
			Recipient: g.UserEmail,
		})
	}
}
