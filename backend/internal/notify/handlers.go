package notify

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
)

// Mount attaches notification settings routes (System.Configure only). It takes
// the auth service directly (not app.Deps) so the app package can depend on
// notify without an import cycle.
func Mount(r chi.Router, a *auth.Service, svc *Service) {
	h := &handler{svc: svc}
	r.Group(func(pr chi.Router) {
		pr.Use(a.RequireAuth)
		pr.With(a.RequirePermission("System.Configure")).Get("/notifications", h.get)
		pr.With(a.RequirePermission("System.Configure")).Put("/notifications", h.put)
		pr.With(a.RequirePermission("System.Configure")).Post("/notifications/test", h.test)
		pr.With(a.RequirePermission("System.Configure")).Get("/notifications/events", h.events)
	})
}

type handler struct {
	svc *Service
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	red, err := h.svc.Redacted(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not load settings")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, red)
}

func (h *handler) put(w http.ResponseWriter, r *http.Request) {
	var cfg Config
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&cfg); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.svc.Save(r.Context(), &cfg); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save settings")
		return
	}
	red, _ := h.svc.Redacted(r.Context())
	httpx.WriteJSON(w, http.StatusOK, red)
}

func (h *handler) test(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Channel string `json:"channel"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.svc.SendTest(r.Context(), body.Channel); err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// events lists the event-type catalogue for the UI matrix.
func (h *handler) events(w http.ResponseWriter, r *http.Request) {
	out := make([]map[string]string, 0, len(AllEventTypes))
	for _, e := range AllEventTypes {
		out = append(out, map[string]string{"key": e.Key, "label": e.Label})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"events": out})
}
