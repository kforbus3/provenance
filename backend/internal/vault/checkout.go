package vault

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/notify"
)

// mountCheckout registers the check-out routes. Requesters (any authenticated user
// with access to a secret) check out; approvers (Credential.Approve) decide.
func (h *handler) mountCheckout(r chi.Router, requireApprove func(http.Handler) http.Handler) {
	r.Post("/vault/secrets/{id}/checkout", h.requestCheckout)
	r.Get("/vault/checkouts", h.myCheckouts)
	r.Post("/vault/checkouts/{coid}/checkin", h.checkin)

	r.With(requireApprove).Get("/vault/checkouts/approvals", h.listCheckoutApprovals)
	r.With(requireApprove).Post("/vault/checkouts/{coid}/approve", h.approveCheckout)
	r.With(requireApprove).Post("/vault/checkouts/{coid}/deny", h.denyCheckout)
}

type checkoutReq struct {
	Reason  string `json:"reason"`
	Minutes int    `json:"minutes"`
}

func (h *handler) requestCheckout(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	var rq checkoutReq
	_ = decode(w, r, &rq)
	p := auth.MustPrincipal(r)
	if h.effectiveAccess(r, p, id) == "" {
		httpx.WriteError(w, http.StatusForbidden, "you do not have access to that credential")
		return
	}
	secret, err := h.d.Store.GetVaultSecret(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "credential not found")
		return
	}
	if secret.AccessPolicy == "open" {
		httpx.WriteError(w, http.StatusBadRequest, "this credential does not require check-out")
		return
	}
	minutes := rq.Minutes
	if minutes <= 0 {
		minutes = 60
	}
	if minutes > 480 {
		minutes = 480
	}
	status := "active"
	if secret.AccessPolicy == "approval" {
		status = "pending"
	}
	co, err := h.d.Store.CreateVaultCheckout(r.Context(), id, p.UserID, rq.Reason, status, time.Duration(minutes)*time.Minute)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create check-out")
		return
	}
	h.audit(r, "credential.checkout_request", id, map[string]any{"name": secret.Name, "status": status, "minutes": minutes})
	if status == "pending" && h.d.Notify != nil {
		h.d.Notify.Notify(r.Context(), notify.Event{
			Type: notify.EventApprovalPending, Severity: notify.SeverityInfo,
			Title: "Credential check-out pending approval",
			Body:  p.Username + " requested check-out of credential \"" + secret.Name + "\". Review it under Credentials.",
		})
	}
	httpx.WriteJSON(w, http.StatusCreated, co)
}

func (h *handler) myCheckouts(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	cos, err := h.d.Store.ListMyVaultCheckouts(r.Context(), p.UserID, 50)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list check-outs")
		return
	}
	if cos == nil {
		cos = []models.VaultCheckout{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"checkouts": cos})
}

func (h *handler) checkin(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "coid")
	if !ok {
		return
	}
	p := auth.MustPrincipal(r)
	co, err := h.d.Store.GetVaultCheckout(r.Context(), id)
	if err != nil || co.UserID != p.UserID {
		httpx.WriteError(w, http.StatusNotFound, "check-out not found")
		return
	}
	if co.Status != "active" && co.Status != "pending" {
		httpx.WriteError(w, http.StatusConflict, "this check-out is already "+co.Status)
		return
	}
	okd, err := h.d.Store.SetVaultCheckoutStatus(r.Context(), id, co.Status, "checked_in", nil)
	if err != nil || !okd {
		httpx.WriteError(w, http.StatusConflict, "could not check in")
		return
	}
	h.audit(r, "credential.checkin", co.SecretID, nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "checked_in"})
}

func (h *handler) listCheckoutApprovals(w http.ResponseWriter, r *http.Request) {
	cos, err := h.d.Store.ListPendingVaultCheckouts(r.Context(), 100)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list approvals")
		return
	}
	if cos == nil {
		cos = []models.VaultCheckout{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"checkouts": cos})
}

func (h *handler) approveCheckout(w http.ResponseWriter, r *http.Request) {
	h.decideCheckout(w, r, "active")
}
func (h *handler) denyCheckout(w http.ResponseWriter, r *http.Request) {
	h.decideCheckout(w, r, "denied")
}

func (h *handler) decideCheckout(w http.ResponseWriter, r *http.Request, to string) {
	id, ok := parseID(w, r, "coid")
	if !ok {
		return
	}
	p := auth.MustPrincipal(r)
	co, err := h.d.Store.GetVaultCheckout(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "check-out not found")
		return
	}
	if co.Status != "pending" {
		httpx.WriteError(w, http.StatusConflict, "this check-out is already "+co.Status)
		return
	}
	if co.UserID == p.UserID {
		httpx.WriteError(w, http.StatusForbidden, "you cannot approve your own check-out request")
		return
	}
	okd, err := h.d.Store.SetVaultCheckoutStatus(r.Context(), id, "pending", to, &p.UserID)
	if err != nil || !okd {
		httpx.WriteError(w, http.StatusConflict, "could not decide check-out")
		return
	}
	action := "credential.checkout_approve"
	if to == "denied" {
		action = "credential.checkout_deny"
	}
	h.audit(r, action, co.SecretID, map[string]any{"requester": co.UserID.String()})
	updated, _ := h.d.Store.GetVaultCheckout(r.Context(), id)
	httpx.WriteJSON(w, http.StatusOK, updated)
}
