package admin

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/store"
)

func (h *handler) listSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := h.d.Store.ListSettings(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list settings")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"settings": settings})
}

func (h *handler) getSetting(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	value, err := h.d.Store.GetSetting(r.Context(), key)
	if err != nil {
		if err == store.ErrNotFound {
			httpx.WriteError(w, http.StatusNotFound, "setting not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "could not load setting")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"key": key, "value": value})
}

func (h *handler) setSetting(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	if key == "" {
		httpx.WriteError(w, http.StatusBadRequest, "key is required")
		return
	}
	var value json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&value); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.d.Store.SetSetting(r.Context(), key, value); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save setting")
		return
	}
	h.audit(r, "settings.update", "setting", key, nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"key": key, "value": value})
}
