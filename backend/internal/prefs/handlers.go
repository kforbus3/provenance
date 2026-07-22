// Package prefs exposes a per-user UI preference store: small JSON values, keyed by a
// short whitelisted key, that follow a user across browsers/devices (e.g. the
// Dashboard's customizable Quick Connect list). Every operation is scoped to the
// authenticated user's own id — a user can only read and write their own preferences —
// so no extra permission is required beyond being signed in.
package prefs

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
)

// allowedKeys whitelists the preference keys the API will store, so this can't be used
// as an arbitrary per-user blob store. Add keys here as new personalizations ship.
var allowedKeys = map[string]bool{
	"dashboard.quickConnect": true,
}

const maxValueBytes = 64 << 10 // 64 KiB is ample for UI preferences

// Mount attaches the preference routes. Auth only — access is self-scoped.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Get("/preferences/{key}", h.get)
		pr.Put("/preferences/{key}", h.put)
	})
}

type handler struct{ d *app.Deps }

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	if !allowedKeys[key] {
		httpx.WriteError(w, http.StatusNotFound, "unknown preference")
		return
	}
	p := auth.MustPrincipal(r)
	v, err := h.d.Store.GetUserPreference(r.Context(), p.UserID, key)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not load preference")
		return
	}
	if v == nil {
		// No value set — return null so the client applies its own default.
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"key": key, "value": nil})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"key": key, "value": json.RawMessage(v)})
}

func (h *handler) put(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	if !allowedKeys[key] {
		httpx.WriteError(w, http.StatusNotFound, "unknown preference")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxValueBytes+1))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if len(body) > maxValueBytes {
		httpx.WriteError(w, http.StatusRequestEntityTooLarge, "preference too large")
		return
	}
	// Store the client's "value" field verbatim (validated as JSON).
	var wrapper struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil || len(wrapper.Value) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "value must be valid JSON")
		return
	}
	if !json.Valid(wrapper.Value) {
		httpx.WriteError(w, http.StatusBadRequest, "value must be valid JSON")
		return
	}
	p := auth.MustPrincipal(r)
	if err := h.d.Store.SetUserPreference(r.Context(), p.UserID, key, wrapper.Value); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save preference")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"key": key, "value": wrapper.Value})
}
