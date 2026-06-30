package auditfwd

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
)

// Mount attaches audit-forwarding settings routes (System.Configure only). It
// takes the auth service directly to avoid an app.Deps import cycle.
func Mount(r chi.Router, a *auth.Service, f *Forwarder) {
	h := &handler{f: f}
	r.Group(func(pr chi.Router) {
		pr.Use(a.RequireAuth)
		pr.With(a.RequirePermission("System.Configure")).Get("/audit/forwarding", h.get)
		pr.With(a.RequirePermission("System.Configure")).Put("/audit/forwarding", h.put)
		pr.With(a.RequirePermission("System.Configure")).Post("/audit/forwarding/test", h.test)
	})
}

type handler struct{ f *Forwarder }

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.f.LoadConfig(r.Context()))
}

func (h *handler) put(w http.ResponseWriter, r *http.Request) {
	var c Config
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&c); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.f.SaveConfig(r.Context(), c); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save settings")
		return
	}
	httpx.Audit(r, h.f.store, models.AuditEvent{Action: "system.audit_forwarding", TargetKind: "system",
		Detail: map[string]any{"enabled": c.Enabled, "type": c.Type}})
	httpx.WriteJSON(w, http.StatusOK, c)
}

func (h *handler) test(w http.ResponseWriter, r *http.Request) {
	var c Config
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&c); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.f.SendTest(c); err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
