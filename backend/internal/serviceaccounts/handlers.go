// Package serviceaccounts exposes management of service accounts (non-human
// identities) and their API tokens. All routes require ServiceAccount.Manage.
// A service account is a users row carrying roles + group host-access; a token
// authenticates as it. Creating/assigning is guarded so a manager can't grant a
// service account permissions they do not themselves hold (no privilege
// escalation); super admins are unrestricted.
package serviceaccounts

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
)

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{1,62}$`)

// Mount attaches service-account routes, all gated by ServiceAccount.Manage.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(d.Auth.RequirePermission("ServiceAccount.Manage"))
		pr.Get("/service-accounts", h.list)
		pr.Post("/service-accounts", h.create)
		pr.Patch("/service-accounts/{id}", h.update)
		pr.Delete("/service-accounts/{id}", h.remove)
		pr.Get("/service-accounts/{id}/tokens", h.listTokens)
		pr.Post("/service-accounts/{id}/tokens", h.createToken)
		pr.Delete("/service-accounts/{id}/tokens/{tokenId}", h.revokeToken)
	})
}

type handler struct{ d *app.Deps }

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	sas, err := h.d.Store.ListServiceAccounts(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list service accounts")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"serviceAccounts": sas})
}

type createReq struct {
	Username    string      `json:"username"`
	DisplayName string      `json:"displayName"`
	RoleIDs     []uuid.UUID `json:"roleIds"`
	GroupIDs    []uuid.UUID `json:"groupIds"`
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var req createReq
	if err := decode(w, r, &req); err != nil {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if !nameRe.MatchString(req.Username) {
		httpx.WriteError(w, http.StatusBadRequest, "username must be 2-63 chars: letters, digits, . _ -")
		return
	}
	if err := h.ensureCanGrant(r, req.RoleIDs); err != nil {
		httpx.WriteError(w, http.StatusForbidden, err.Error())
		return
	}
	sa, err := h.d.Store.CreateServiceAccount(r.Context(), req.Username, req.DisplayName)
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, "could not create — the name may already be in use")
		return
	}
	if len(req.RoleIDs) > 0 {
		_ = h.d.Store.SetServiceAccountRoles(r.Context(), sa.ID, req.RoleIDs)
	}
	if len(req.GroupIDs) > 0 {
		_ = h.d.Store.SetServiceAccountGroups(r.Context(), sa.ID, req.GroupIDs)
	}
	h.audit(r, "service_account.create", sa.ID, map[string]any{"username": sa.Username})
	fresh, _ := h.d.Store.GetServiceAccount(r.Context(), sa.ID)
	if fresh != nil {
		sa = fresh
	}
	httpx.WriteJSON(w, http.StatusCreated, sa)
}

type updateReq struct {
	DisplayName *string      `json:"displayName"`
	Disabled    *bool        `json:"disabled"`
	RoleIDs     *[]uuid.UUID `json:"roleIds"`
	GroupIDs    *[]uuid.UUID `json:"groupIds"`
}

func (h *handler) update(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	var req updateReq
	if err := decode(w, r, &req); err != nil {
		return
	}
	if req.RoleIDs != nil {
		if err := h.ensureCanGrant(r, *req.RoleIDs); err != nil {
			httpx.WriteError(w, http.StatusForbidden, err.Error())
			return
		}
		if err := h.d.Store.SetServiceAccountRoles(r.Context(), id, *req.RoleIDs); err != nil {
			httpx.WriteError(w, http.StatusNotFound, "no such service account")
			return
		}
	}
	if req.GroupIDs != nil {
		if err := h.d.Store.SetServiceAccountGroups(r.Context(), id, *req.GroupIDs); err != nil {
			httpx.WriteError(w, http.StatusNotFound, "no such service account")
			return
		}
	}
	if req.Disabled != nil {
		if err := h.d.Store.SetServiceAccountDisabled(r.Context(), id, *req.Disabled); err != nil {
			httpx.WriteError(w, http.StatusNotFound, "no such service account")
			return
		}
	}
	h.audit(r, "service_account.update", id, nil)
	sa, err := h.d.Store.GetServiceAccount(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such service account")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sa)
}

func (h *handler) remove(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	if err := h.d.Store.DeleteServiceAccount(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such service account")
		return
	}
	h.audit(r, "service_account.delete", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) listTokens(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	tokens, err := h.d.Store.ListAPITokens(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list tokens")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

type createTokenReq struct {
	Name          string `json:"name"`
	ExpiresInDays int    `json:"expiresInDays"` // 0 = no expiry
}

func (h *handler) createToken(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	if _, err := h.d.Store.GetServiceAccount(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such service account")
		return
	}
	var req createTokenReq
	if err := decode(w, r, &req); err != nil {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "token name is required")
		return
	}
	var expiresAt *time.Time
	if req.ExpiresInDays > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour)
		expiresAt = &t
	}
	secret, hash, prefix, err := auth.NewAPIToken()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not generate token")
		return
	}
	tok, err := h.d.Store.CreateAPIToken(r.Context(), id, req.Name, hash, prefix, auth.MustPrincipal(r).UserID, expiresAt)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create token")
		return
	}
	tok.Secret = secret // returned exactly once
	h.audit(r, "service_account.token.create", id, map[string]any{"tokenName": req.Name, "tokenId": tok.ID})
	httpx.WriteJSON(w, http.StatusCreated, tok)
}

func (h *handler) revokeToken(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	tokenID, ok := parseID(w, r, "tokenId")
	if !ok {
		return
	}
	if err := h.d.Store.RevokeAPIToken(r.Context(), id, tokenID); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such token")
		return
	}
	h.audit(r, "service_account.token.revoke", id, map[string]any{"tokenId": tokenID})
	w.WriteHeader(http.StatusNoContent)
}

// ensureCanGrant blocks privilege escalation: the caller may only assign roles
// whose permissions they themselves hold. Super admins are unrestricted.
func (h *handler) ensureCanGrant(r *http.Request, roleIDs []uuid.UUID) error {
	p := auth.MustPrincipal(r)
	if p.IsSuperAdmin {
		return nil
	}
	for _, rid := range roleIDs {
		perms, err := h.d.Store.RolePermissions(r.Context(), rid)
		if err != nil {
			return errString("unknown role")
		}
		for _, perm := range perms {
			if !p.Has(perm) {
				return errString("you cannot grant a role that includes permissions you do not hold")
			}
		}
	}
	return nil
}

func (h *handler) audit(r *http.Request, action string, target uuid.UUID, detail map[string]any) {
	p := auth.MustPrincipal(r)
	if detail == nil {
		detail = map[string]any{}
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: action,
		TargetKind: "service_account", TargetID: target.String(), Detail: detail,
	})
}

// --- small helpers ---

type errString string

func (e errString) Error() string { return string(e) }

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return err
	}
	return nil
}

func parseID(w http.ResponseWriter, r *http.Request, key string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, key))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return uuid.Nil, false
	}
	return id, true
}
