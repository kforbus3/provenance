// Package uebaapi surfaces user-and-entity behavior analytics: access-pattern
// anomalies computed on demand from Fleet's session records. Gated by Audit.View
// (behavioral analytics is audit-adjacent). See internal/ueba.
package uebaapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/ueba"
)

const (
	lookback     = 30 * 24 * time.Hour // baseline window
	recentWindow = 24 * time.Hour      // "recent" activity compared against the baseline
	maxSessions  = 20000               // bound the scan
)

// Mount attaches the UEBA route, gated by Audit.View.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(d.Auth.RequirePermission("Audit.View"))
		pr.Get("/ueba/anomalies", h.anomalies)
	})
}

type handler struct{ d *app.Deps }

func (h *handler) anomalies(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-lookback)
	sessions, err := h.d.Store.SessionsForUEBA(r.Context(), since, maxSessions)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not load sessions")
		return
	}
	anomalies := ueba.Analyze(sessions, time.Now(), recentWindow)
	if anomalies == nil {
		anomalies = []ueba.Anomaly{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"anomalies":    anomalies,
		"analyzed":     len(sessions),
		"lookbackDays": int(lookback.Hours() / 24),
		"recentHours":  int(recentWindow.Hours()),
		"generatedAt":  time.Now().Format(time.RFC3339),
	})
}
