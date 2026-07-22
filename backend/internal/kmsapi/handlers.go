// Package kmsapi exposes read-only status for the external KMS/HSM backend that
// envelope-protects Fleet's master passphrases (see internal/kms). It surfaces the
// configured provider and a live health check in-product so an operator (or an
// auditor) can confirm the CA and vault passphrases are protected by a KMS without
// shell access. Configuration itself is boot-time environment only — there is no
// write path here.
package kmsapi

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/kms"
)

// Mount attaches the KMS status route, gated by System.Configure.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(d.Auth.RequirePermission("System.Configure"))
		pr.Get("/kms/status", h.status)
	})
}

type handler struct{ d *app.Deps }

type statusResponse struct {
	Provider            string `json:"provider"`
	Enabled             bool   `json:"enabled"`
	KeyID               string `json:"keyId"`
	CAPassphraseWrap    bool   `json:"caPassphraseWrapped"`
	VaultPassphraseWrap bool   `json:"vaultPassphraseWrapped"`
	Healthy             bool   `json:"healthy"`
	Health              string `json:"health"` // "ok" | "n/a" | error message
}

func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	cfg := h.d.Cfg
	resp := statusResponse{
		Provider:            cfg.KMSProvider,
		Enabled:             cfg.KMSEnabled(),
		KeyID:               cfg.KMSKeyID,
		CAPassphraseWrap:    cfg.CAKeyPassphraseWrapped != "",
		VaultPassphraseWrap: cfg.VaultPassphraseWrapped != "",
	}
	if !cfg.KMSEnabled() {
		resp.Healthy = true
		resp.Health = "n/a"
		httpx.WriteJSON(w, http.StatusOK, resp)
		return
	}
	prov, err := kms.New(cfg.KMS())
	if err != nil {
		resp.Health = err.Error()
		httpx.WriteJSON(w, http.StatusOK, resp)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	if err := prov.Health(ctx); err != nil {
		resp.Health = err.Error()
		httpx.WriteJSON(w, http.StatusOK, resp)
		return
	}
	resp.Healthy = true
	resp.Health = "ok"
	httpx.WriteJSON(w, http.StatusOK, resp)
}
