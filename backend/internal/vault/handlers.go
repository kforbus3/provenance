// Package vault is the credential vault: it stores static credentials (passwords,
// SSH keys, API keys) encrypted at rest and controls who may reveal or (later)
// inject them. Secret material is sealed with secretbox under a dedicated vault
// passphrase; the plaintext leaves the server only through the audited reveal
// endpoint, and only to callers holding Credential.View plus access to that secret.
package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/credresolve"
	"github.com/kforbus3/provenance/backend/internal/extsecret"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/secretbox"
	"github.com/kforbus3/provenance/backend/internal/sshgw"
	"github.com/kforbus3/provenance/backend/internal/store"
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

		// The external secrets-manager CONNECTION is deployment configuration, not a
		// credential, so it is gated on System.Configure like OIDC and LDAP — a
		// Credential.Manage holder curates secrets, they do not repoint the manager
		// every secret is read from.
		pr.With(d.Auth.RequirePermission("System.Configure")).Get("/settings/extsecret", h.extSecretGet)
		pr.With(d.Auth.RequirePermission("System.Configure")).Put("/settings/extsecret", h.extSecretPut)
		pr.With(d.Auth.RequirePermission("System.Configure")).Post("/settings/extsecret/test", h.extSecretTest)

		// Management: Credential.Manage.
		pr.With(d.Auth.RequirePermission("Credential.Manage")).Post("/vault/secrets", h.create)
		pr.With(d.Auth.RequirePermission("Credential.Manage")).Put("/vault/secrets/{id}", h.update)
		pr.With(d.Auth.RequirePermission("Credential.Manage")).Delete("/vault/secrets/{id}", h.del)
		// Which machines a LUKS recovery credential actually opens. Read-only and
		// no secret material, so Credential.View is enough -- the point is to make
		// the dependency visible BEFORE somebody tries to delete it, not only in
		// the refusal afterwards.
		pr.With(d.Auth.RequirePermission("Credential.View")).Get("/vault/secrets/{id}/machines", h.dependentMachines)
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
// PROV_VAULT_PASSPHRASE, or it equals the CA passphrase).
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
	secret, err := h.d.Store.GetVaultSecret(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "credential not found")
		return
	}
	// A locally-sealed secret needs the vault key; an external-backed one is fetched
	// from the manager and never touches it.
	var key []byte
	if secret.ExternalProvider == "" {
		if key, ok = h.vaultKey(w); !ok {
			return
		}
	}
	plaintext, err := credresolve.Open(r.Context(), h.d.Store, secret, key, h.d.Cfg.ExtSecret())
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "could not resolve credential: "+err.Error())
		return
	}
	h.audit(r, "credential.reveal", id, secretDetail(secret))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"secret": string(plaintext)})
}

type secretReq struct {
	Name             string `json:"name"`
	Folder           string `json:"folder"`
	Type             string `json:"type"`
	Username         string `json:"username"`
	Target           string `json:"target"`
	Description      string `json:"description"`
	Secret           string `json:"secret"`           // plaintext; sealed server-side, never stored raw
	ExternalProvider string `json:"externalProvider"` // set = external-backed (e.g. "vault-kv")
	ExternalRef      string `json:"externalRef"`      // manager reference, e.g. "secret/db/prod#password"
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
		Username: rq.Username, Target: rq.Target, Description: rq.Description,
		ExternalProvider: strings.TrimSpace(rq.ExternalProvider), ExternalRef: strings.TrimSpace(rq.ExternalRef),
		CreatedBy: createdBy,
	}
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var rq secretReq
	if err := decode(w, r, &rq); err != nil {
		return
	}
	if strings.TrimSpace(rq.Name) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	external := strings.TrimSpace(rq.ExternalProvider) != ""
	var sealed string // empty for external-backed secrets (no local material)
	if external {
		if !extsecret.Supported(strings.TrimSpace(rq.ExternalProvider)) {
			httpx.WriteError(w, http.StatusBadRequest, "unsupported external secrets provider")
			return
		}
		if strings.TrimSpace(rq.ExternalRef) == "" {
			httpx.WriteError(w, http.StatusBadRequest, "an external reference is required for an external-backed credential")
			return
		}
		if !h.d.Cfg.ExtSecretEnabled() {
			httpx.WriteError(w, http.StatusBadRequest, "no external secrets manager is configured (set PROV_EXTSECRET_*)")
			return
		}
	} else {
		if rq.Secret == "" {
			httpx.WriteError(w, http.StatusBadRequest, "a secret value is required")
			return
		}
		key, ok := h.vaultKey(w)
		if !ok {
			return
		}
		var err error
		if sealed, err = secretbox.Seal(key, []byte(rq.Secret)); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not seal credential")
			return
		}
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
	existing, err := h.d.Store.GetVaultSecret(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "credential not found")
		return
	}
	if existing.ExternalProvider != "" && rq.Secret != "" {
		httpx.WriteError(w, http.StatusBadRequest, "external-backed credentials store no local value; change it in the external secrets manager")
		return
	}
	if err := h.d.Store.UpdateVaultSecretMeta(r.Context(), id, rq.toInput(p.UserID)); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update credential")
		return
	}
	// A non-empty secret rotates the value into a new version (local secrets only).
	if rq.Secret != "" && existing.ExternalProvider == "" {
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

// dependentMachines lists the machines a LUKS recovery credential unlocks.
//
// Empty for every other kind of credential, and for a LUKS one no machine was
// imaged from -- both are ordinary answers, not errors.
func (h *handler) dependentMachines(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	secret, err := h.d.Store.GetVaultSecret(r.Context(), id)
	if err != nil || secret == nil {
		httpx.WriteError(w, http.StatusNotFound, "no such credential")
		return
	}
	out := []models.ImagingMachine{}
	if strings.HasPrefix(secret.Name, "luks/") && secret.Target != "" {
		ms, merr := h.d.Store.MachinesImagedFrom(r.Context(), secret.Target)
		if merr != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not read the machines")
			return
		}
		out = ms
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"machines": out, "count": len(out)})
}

func (h *handler) del(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	secret, _ := h.d.Store.GetVaultSecret(r.Context(), id)

	// A LUKS recovery credential that machines still depend on.
	//
	// A machine's LUKS header is written once, at imaging time, and an update
	// never touches it -- RAUC writes through /dev/mapper/luks-rootfs-*, so a
	// bundle built from a newer image replaces the operating system and leaves
	// the keyslots as the original image made them. A machine therefore keeps
	// the passphrase of the image it was IMAGED from, however new the release it
	// is running.
	//
	// That makes this deletion the quiet, irreversible one: the fleet "moved to"
	// a new image months ago, the old image's credential looks like leftovers,
	// and deleting it destroys the only recovery key for every machine imaged
	// from it. Nothing about those machines' current version points back to it,
	// and nothing goes wrong until somebody is standing at a console that will
	// not boot.
	//
	// Refused rather than warned, because a warning in an API response is read
	// by nobody. ?force=true is the deliberate override, and it is audited as
	// such -- retiring the machines first is the ordinary path.
	if secret != nil && strings.HasPrefix(secret.Name, "luks/") && secret.Target != "" {
		machines, merr := h.d.Store.MachinesImagedFrom(r.Context(), secret.Target)
		if merr != nil {
			// Cannot answer the question, so do not act on the answer. Deleting
			// here on the assumption that nothing depends on it is the one
			// outcome that cannot be undone.
			httpx.WriteError(w, http.StatusInternalServerError,
				"could not check which machines depend on this recovery passphrase; "+
					"nothing was deleted")
			return
		}
		if len(machines) > 0 && !httpx.QueryBool(r, "force") {
			httpx.WriteError(w, http.StatusConflict, fmt.Sprintf(
				"%d machine%s still unlock%s with this passphrase, because a machine keeps the "+
					"LUKS keys of the image it was imaged from however many updates it has had "+
					"since: %s. Deleting it destroys their only recovery key. Retire them first, "+
					"or repeat with ?force=true.",
				len(machines), plural(len(machines)), verbS(len(machines)),
				machineNames(machines)))
			return
		}
		if len(machines) > 0 {
			h.audit(r, "credential.delete.forced", id, map[string]any{
				"name": secret.Name, "dependentMachines": len(machines),
			})
		}
	}

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

// machineNames renders a bounded list of machines for an error message. Bounded
// because an image used fleet-wide has hundreds, and an error nobody can read is
// the same as no error.
func machineNames(ms []models.ImagingMachine) string {
	const max = 6
	names := make([]string, 0, len(ms))
	for _, m := range ms {
		n := strings.TrimSpace(m.Hostname)
		if n == "" {
			n = m.ID
		}
		names = append(names, n)
		if len(names) == max && len(ms) > max {
			return strings.Join(names, ", ") + fmt.Sprintf(" and %d more", len(ms)-max)
		}
	}
	return strings.Join(names, ", ")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// verbS keeps the message grammatical for one machine as well as many, because a
// message that reads as broken is trusted less than one that does not.
func verbS(n int) string {
	if n == 1 {
		return "s"
	}
	return ""
}
