// Package lifecycle serves the credential/certificate expiry & rotation
// dashboard: a single read-only view of API tokens nearing (or past) expiry or
// unused, vault credentials overdue for rotation, aging user passwords, and aging
// CA keys. It exposes only metadata — never secret material — and is gated by
// System.Configure (the admin/settings gate).
package lifecycle

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/httpx"
)

// Mount attaches the lifecycle routes, gated by System.Configure.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(d.Auth.RequirePermission("System.Configure"))
		pr.Get("/lifecycle/expiry", h.expiry)
	})
}

type handler struct{ d *app.Deps }

// expiry returns the current lifecycle attention items plus per-status counts, so
// the UI can show a summary and a table without recomputing.
func (h *handler) expiry(w http.ResponseWriter, r *http.Request) {
	items, err := h.d.Store.LifecycleReport(r.Context(), time.Now())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not compute lifecycle report")
		return
	}
	counts := map[string]int{}
	for _, it := range items {
		counts[it.Status]++
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"counts":      counts,
		"generatedAt": time.Now(),
	})
}
