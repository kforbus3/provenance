// Package vault is the credential vault: it stores static credentials (passwords,
// SSH keys, API keys) encrypted at rest and controls who may reveal or (later)
// inject them. Secret material is sealed with secretbox under a dedicated vault
// passphrase; the plaintext leaves the server only through the audited reveal
// endpoint, and only to callers holding Credential.View plus access to that secret.
package vault

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
	"github.com/fleet-terminal/backend/internal/secretbox"
	"github.com/fleet-terminal/backend/internal/sshgw"
	"github.com/fleet-terminal/backend/internal/store"
)

type handler struct {
	d  *app.Deps
	gw *sshgw.Gateway
}

// Mount registers the credential-vault routes.
func Mount(r chi.Router, d *app.Deps, gw *sshgw.Gateway) {
	h := &handler{d: d, gw: gw}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		// Read + reveal: any authenticated user; the handler scopes to what they may
		// see (Credential.Manage → all; otherwise granted secrets only).
		pr.Get("/vault/secrets", h.list)
		pr.Get("/vault/secrets/{id}", h.get)
		pr.Post("/vault/secrets/{id}/reveal", h.reveal)

		// Management: Credential.Manage.
		pr.With(d.Auth.RequirePermission("Credential.Manage")).Post("/vault/secrets", h.create)
		pr.With(d.Auth.RequirePermission("Credential.Manage")).Put("/vault/secrets/{id}", h.update)
		pr.With(d.Auth.RequirePermission("Credential.Manage")).Delete("/vault/secrets/{id}", h.del)
		pr.With(d.Auth.RequirePermission("Credential.Manage")).Get("/vault/secrets/{id}/grants", h.listGrants)
		pr.With(d.Auth.RequirePermission("Credential.Manage")).Post("/vault/secrets/{id}/grants", h.createGrant)
		pr.With(d.Auth.RequirePermission("Credential.Manage")).Delete("/vault/secrets/{id}/grants/{grantId}", h.deleteGrant)
		pr.With(d.Auth.RequirePermission("Credential.Rotate")).Post("/vault/secrets/{id}/rotate", h.rotate)
		pr.With(d.Auth.RequirePermission("Credential.Rotate")).Put("/vault/secrets/{id}/rotation-policy", h.setRotationPolicy)

		// Check-out / approval workflow.
		h.mountCheckout(pr, d.Auth.RequirePermission("Credential.Approve"))
	})
}

// vaultKey resolves the vault encryption passphrase, or writes a 500 and returns
// false if the deployment isn't configured for the vault (production without
// FLEET_VAULT_PASSPHRASE, or it equals the CA passphrase).
func (h *handler) vaultKey(w http.ResponseWriter) ([]byte, bool) {
	key, err := h.d.Cfg.VaultKey()
	if err != nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return nil, false
	}
	return key, true
}

func parseID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, name))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return uuid.Nil, false
	}
	return id, true
}

// effectiveAccess returns the caller's access to a secret: "manage" if they hold
// Credential.Manage, otherwise their highest per-secret grant ("view"/"use"/
// "manage"), or "" for none.
func (h *handler) effectiveAccess(r *http.Request, p *auth.Principal, secretID uuid.UUID) string {
	if p.Has("Credential.Manage") {
		return "manage"
	}
	acc, _ := h.d.Store.UserSecretAccess(r.Context(), p.UserID, secretID)
	return acc
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	var (
		secrets []models.VaultSecret
		err     error
	)
	if p.Has("Credential.Manage") {
		secrets, err = h.d.Store.ListAllVaultSecrets(r.Context())
	} else {
		secrets, err = h.d.Store.ListAccessibleVaultSecrets(r.Context(), p.UserID)
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list credentials")
		return
	}
	if secrets == nil {
		secrets = []models.VaultSecret{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"secrets": secrets})
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	p := auth.MustPrincipal(r)
	access := h.effectiveAccess(r, p, id)
	if access == "" {
		httpx.WriteError(w, http.StatusNotFound, "credential not found") // don't leak existence
		return
	}
	secret, err := h.d.Store.GetVaultSecret(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "credential not found")
		return
	}
	secret.Access = access
	httpx.WriteJSON(w, http.StatusOK, secret)
}

// reveal returns the plaintext of a credential. Gated by Credential.View (or
// Manage) plus access to the specific secret, and always audited.
func (h *handler) reveal(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	p := auth.MustPrincipal(r)
	access := h.effectiveAccess(r, p, id)
	// A per-secret grant scopes WHICH secrets; Credential.View is the capability to
	// reveal at all. Managers bypass. No access → 404 (don't leak existence).
	if access == "" {
		httpx.WriteError(w, http.StatusNotFound, "credential not found")
		return
	}
	if !p.Has("Credential.Manage") && !p.Has("Credential.View") {
		httpx.WriteError(w, http.StatusForbidden, "you do not have permission to reveal credentials")
		return
	}
	// A credential with a check-out policy may only be revealed while the caller
	// holds an active check-out (approved, if the policy requires it).
	if pol, _ := h.d.Store.GetVaultSecret(r.Context(), id); pol != nil && pol.AccessPolicy != "open" {
		active, _ := h.d.Store.HasActiveCheckout(r.Context(), id, p.UserID)
		if !active {
			httpx.WriteError(w, http.StatusForbidden, "check out this credential before revealing it")
			return
		}
	}
	key, ok := h.vaultKey(w)
	if !ok {
		return
	}
	sealed, err := h.d.Store.GetVaultSecretSealed(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "credential not found")
		return
	}
	plaintext, err := secretbox.Open(key, sealed)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not decrypt credential")
		return
	}
	secret, _ := h.d.Store.GetVaultSecret(r.Context(), id)
	h.audit(r, "credential.reveal", id, secretDetail(secret))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"secret": string(plaintext)})
}

type secretReq struct {
	Name        string `json:"name"`
	Folder      string `json:"folder"`
	Type        string `json:"type"`
	Username    string `json:"username"`
	Target      string `json:"target"`
	Description string `json:"description"`
	Secret      string `json:"secret"` // plaintext; sealed server-side, never stored raw
}

func (rq secretReq) toInput(createdBy uuid.UUID) store.VaultSecretInput {
	t := rq.Type
	switch t {
	case "password", "ssh_key", "api_key", "generic":
	default:
		t = "password"
	}
	return store.VaultSecretInput{
		Name: strings.TrimSpace(rq.Name), Folder: strings.TrimSpace(rq.Folder), Type: t,
		Username: rq.Username, Target: rq.Target, Description: rq.Description, CreatedBy: createdBy,
	}
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var rq secretReq
	if err := decode(w, r, &rq); err != nil {
		return
	}
	if strings.TrimSpace(rq.Name) == "" || rq.Secret == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name and secret are required")
		return
	}
	key, ok := h.vaultKey(w)
	if !ok {
		return
	}
	sealed, err := secretbox.Seal(key, []byte(rq.Secret))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not seal credential")
		return
	}
	p := auth.MustPrincipal(r)
	secret, err := h.d.Store.CreateVaultSecret(r.Context(), rq.toInput(p.UserID), sealed)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create credential")
		return
	}
	h.audit(r, "credential.create", secret.ID, secretDetail(secret))
	httpx.WriteJSON(w, http.StatusCreated, secret)
}

func (h *handler) update(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	var rq secretReq
	if err := decode(w, r, &rq); err != nil {
		return
	}
	if strings.TrimSpace(rq.Name) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	p := auth.MustPrincipal(r)
	if err := h.d.Store.UpdateVaultSecretMeta(r.Context(), id, rq.toInput(p.UserID)); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update credential")
		return
	}
	// A non-empty secret rotates the value into a new version.
	if rq.Secret != "" {
		key, ok := h.vaultKey(w)
		if !ok {
			return
		}
		sealed, err := secretbox.Seal(key, []byte(rq.Secret))
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not seal credential")
			return
		}
		if _, err := h.d.Store.AddVaultSecretVersion(r.Context(), id, sealed, p.UserID); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not store new version")
			return
		}
		h.audit(r, "credential.rotate", id, nil)
	}
	secret, err := h.d.Store.GetVaultSecret(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "credential not found")
		return
	}
	h.audit(r, "credential.update", id, secretDetail(secret))
	httpx.WriteJSON(w, http.StatusOK, secret)
}

func (h *handler) del(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	secret, _ := h.d.Store.GetVaultSecret(r.Context(), id)
	if err := h.d.Store.DeleteVaultSecret(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete credential")
		return
	}
	h.audit(r, "credential.delete", id, secretDetail(secret))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

// ---- grants ----------------------------------------------------------------

func (h *handler) listGrants(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	grants, err := h.d.Store.ListVaultGrants(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list grants")
		return
	}
	if grants == nil {
		grants = []models.VaultGrant{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"grants": grants})
}

type grantReq struct {
	SubjectKind string `json:"subjectKind"` // user | group
	SubjectID   string `json:"subjectId"`
	Access      string `json:"access"` // view | use | manage
}

func (h *handler) createGrant(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	var rq grantReq
	if err := decode(w, r, &rq); err != nil {
		return
	}
	if rq.SubjectKind != "user" && rq.SubjectKind != "group" {
		httpx.WriteError(w, http.StatusBadRequest, "subjectKind must be user or group")
		return
	}
	access := rq.Access
	switch access {
	case "view", "use", "manage":
	default:
		access = "view"
	}
	subjectID, err := uuid.Parse(rq.SubjectID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid subjectId")
		return
	}
	grant, err := h.d.Store.CreateVaultGrant(r.Context(), id, rq.SubjectKind, subjectID, access)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create grant")
		return
	}
	h.audit(r, "credential.grant", id, map[string]any{"subjectKind": rq.SubjectKind, "subjectId": rq.SubjectID, "access": access})
	httpx.WriteJSON(w, http.StatusCreated, grant)
}

func (h *handler) deleteGrant(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	grantID, ok := parseID(w, r, "grantId")
	if !ok {
		return
	}
	if err := h.d.Store.DeleteVaultGrant(r.Context(), id, grantID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete grant")
		return
	}
	h.audit(r, "credential.revoke_grant", id, map[string]any{"grantId": grantID.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

// ---- helpers ---------------------------------------------------------------

func (h *handler) audit(r *http.Request, action string, secretID uuid.UUID, detail map[string]any) {
	p := auth.MustPrincipal(r)
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: action,
		TargetKind: "credential", TargetID: secretID.String(), Detail: detail,
	})
}

// secretDetail is audit metadata that never includes secret material.
func secretDetail(s *models.VaultSecret) map[string]any {
	if s == nil {
		return nil
	}
	return map[string]any{"name": s.Name, "folder": s.Folder, "type": s.Type}
}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return err
	}
	return nil
}
