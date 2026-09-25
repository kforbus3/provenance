// Package certificates exposes certificate-authority and issued-certificate
// management endpoints (lifecycle: list, rotate CA, revoke, KRL).
package certificates

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/ca"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/models"
)

// Mount attaches certificate management routes.
func Mount(r chi.Router, d *app.Deps, caMgr *ca.CA) {
	h := &handler{d: d, ca: caMgr}
	// Public: the active user CA *public* key(s), in authorized_keys format. The
	// CA public key is not secret (it is installed as TrustedUserCAKeys on every
	// managed host); serving it unauthenticated lets a co-located jump host
	// self-trust the CA on startup and stay current across CA rotation.
	r.Get("/certificates/ca/pub", h.caPub)
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("Certificate.Manage")).Get("/certificates", h.list)
		pr.With(d.Auth.RequirePermission("Certificate.Manage")).Get("/certificates/ca", h.listCA)
		pr.With(d.Auth.RequirePermission("Certificate.Manage")).Post("/certificates/ca/rotate", h.rotate)
		pr.With(d.Auth.RequirePermission("Certificate.Manage")).Get("/certificates/ca/rotation", h.rotationStatus)
		pr.With(d.Auth.RequirePermission("Certificate.Manage")).Post("/certificates/ca/promote", h.promote)
		pr.With(d.Auth.RequirePermission("Certificate.Manage")).Post("/certificates/ca/{id}/retire", h.retire)
		pr.With(d.Auth.RequirePermission("Certificate.Manage")).Get("/certificates/krl", h.krl)
		pr.With(d.Auth.RequirePermission("Certificate.Manage")).Post("/certificates/krl/distribute", h.distribute)
		pr.With(d.Auth.RequirePermission("Certificate.Manage")).Post("/certificates/{serial}/revoke", h.revoke)
	})
}

type handler struct {
	d  *app.Deps
	ca *ca.CA
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	certs, err := h.d.Store.ListCertificates(r.Context(), nil, limit)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list certificates")
		return
	}
	if certs == nil {
		certs = []models.SSHCertificate{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"certificates": certs})
}

// caPub serves the active user CA public key(s) as text/plain (one per line), for
// a host or jump host to install as TrustedUserCAKeys. Unauthenticated by design.
func (h *handler) caPub(w http.ResponseWriter, r *http.Request) {
	keys, err := h.d.Store.ListActiveCAPublicKeys(r.Context(), "user")
	if err != nil || len(keys) == 0 {
		http.Error(w, "no active CA", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(strings.Join(keys, "\n") + "\n"))
}

func (h *handler) listCA(w http.ResponseWriter, r *http.Request) {
	cas, err := h.d.Store.ListCAKeys(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list CAs")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"cas": cas, "activeUserCA": h.ca.PublicKeyAuthorized()})
}

func (h *handler) rotate(w http.ResponseWriter, r *http.Request) {
	// The new key is created TRUSTED, not signing. The previous key goes on signing
	// until every host and the jump host confirm the new one, so a rotation no longer
	// has a window in which new certificates are signed by a key nothing trusts yet.
	if err := h.ca.Rotate(r.Context()); err != nil {
		if errors.Is(err, ca.ErrRotationPending) {
			httpx.WriteError(w, http.StatusConflict, err.Error())
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "rotation failed")
		return
	}
	h.audit(r, "certificate.ca_rotate", h.ca.PendingID(), map[string]any{"signing": h.ca.ActiveID()})
	if h.d.CALifecycle == nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "pending", "pendingId": h.ca.PendingID(),
			"note": "The new key is trusted but not signing. No lifecycle is configured to push and promote it."})
		return
	}
	// Push to every host now, then try to promote. The jump host usually has not
	// fetched the new key yet, so this normally returns "pending"; the background
	// reconcile promotes it within minutes, and the previous key signs until then.
	if h.d.DistributeCATrust != nil {
		pushed, failed, _ := h.d.DistributeCATrust(r.Context())
		h.audit(r, "certificate.ca_trust_distributed", h.ca.PendingID(),
			map[string]any{"pushed": pushed, "failed": failed})
	}
	st, err := h.d.CALifecycle.Advance(r.Context(), false)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "rotation started, but checking it failed: "+err.Error())
		return
	}
	if st.Promoted {
		h.audit(r, "certificate.ca_promote", st.SigningID, map[string]any{"forced": false})
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (h *handler) rotationStatus(w http.ResponseWriter, r *http.Request) {
	if h.d.CALifecycle == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "CA lifecycle not configured")
		return
	}
	st, err := h.d.CALifecycle.Status(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the rotation: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

// promote re-checks a pending rotation now instead of waiting for the reconcile.
// force=true promotes even though some hosts do not confirm the new key -- for hosts
// that are gone for good -- and they will refuse new logins until they take it. It
// never skips the jump host: without it nothing is reachable.
func (h *handler) promote(w http.ResponseWriter, r *http.Request) {
	if h.d.CALifecycle == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "CA lifecycle not configured")
		return
	}
	force := r.URL.Query().Get("force") == "true"
	st, err := h.d.CALifecycle.Advance(r.Context(), force)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if st.Promoted {
		h.audit(r, "certificate.ca_promote", st.SigningID, map[string]any{"forced": force, "hostsNotConfirming": st.OutOfSync})
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

// retire stops trusting a CA key. There was no way to do this: RetireCAKey existed
// and nothing called it, so every key ever created stayed trusted on every host.
func (h *handler) retire(w http.ResponseWriter, r *http.Request) {
	if h.d.CALifecycle == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "CA lifecycle not configured")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid CA id")
		return
	}
	st, err := h.d.CALifecycle.Retire(r.Context(), id)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, app.ErrCAKeyInUse) {
			code = http.StatusConflict
		}
		httpx.WriteError(w, code, err.Error())
		return
	}
	h.audit(r, "certificate.ca_retire", id.String(), map[string]any{"hostsNotConfirming": st.OutOfSync})
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (h *handler) revoke(w http.ResponseWriter, r *http.Request) {
	serial, err := strconv.ParseUint(chi.URLParam(r, "serial"), 10, 64)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid serial")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := h.d.Store.RevokeCertificate(r.Context(), serial, body.Reason); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "revocation failed")
		return
	}
	h.audit(r, "certificate.revoke", strconv.FormatUint(serial, 10), map[string]any{"reason": body.Reason})
	// Push the updated KRL to hosts immediately so the revocation takes effect.
	// hostsFailed is part of the response, not just a log line: those hosts still
	// accept this certificate, so a revocation that reports success while some
	// hosts never got the list would be the most misleading answer possible.
	pushed, failed := 0, 0
	if h.d.DistributeKRL != nil {
		pushed, failed, _ = h.d.DistributeKRL(r.Context())
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "revoked", "hostsUpdated": pushed, "hostsFailed": failed,
	})
}

// distribute pushes the current KRL to all enrolled hosts on demand.
func (h *handler) distribute(w http.ResponseWriter, r *http.Request) {
	if h.d.DistributeKRL == nil {
		httpx.WriteError(w, http.StatusNotImplemented, "distribution unavailable")
		return
	}
	pushed, failed, err := h.d.DistributeKRL(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "distribution failed: "+err.Error())
		return
	}
	h.audit(r, "certificate.krl_distribute", "", map[string]any{"hostsUpdated": pushed, "hostsFailed": failed})
	status := "distributed"
	if failed > 0 {
		status = "partial"
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status": status, "hostsUpdated": pushed, "hostsFailed": failed,
	})
}

func (h *handler) krl(w http.ResponseWriter, r *http.Request) {
	serials, err := h.d.Store.RevokedSerials(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not load KRL")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"revokedSerials": serials})
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
		TargetKind: "certificate", TargetID: targetID, Detail: detail,
	})
}
