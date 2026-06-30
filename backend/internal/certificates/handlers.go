// Package certificates exposes certificate-authority and issued-certificate
// management endpoints (lifecycle: list, rotate CA, revoke, KRL).
package certificates

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/ca"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
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
	if err := h.ca.Rotate(r.Context()); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "rotation failed")
		return
	}
	h.audit(r, "certificate.ca_rotate", h.ca.ActiveID(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "rotated", "activeCa": h.ca.ActiveID()})
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
	pushed := 0
	if h.d.DistributeKRL != nil {
		pushed, _ = h.d.DistributeKRL(r.Context())
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "revoked", "hostsUpdated": pushed})
}

// distribute pushes the current KRL to all enrolled hosts on demand.
func (h *handler) distribute(w http.ResponseWriter, r *http.Request) {
	if h.d.DistributeKRL == nil {
		httpx.WriteError(w, http.StatusNotImplemented, "distribution unavailable")
		return
	}
	pushed, err := h.d.DistributeKRL(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "distribution failed: "+err.Error())
		return
	}
	h.audit(r, "certificate.krl_distribute", "", map[string]any{"hostsUpdated": pushed})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "distributed", "hostsUpdated": pushed})
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
