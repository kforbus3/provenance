package digest

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
)

// Mount attaches digest settings routes (System.Configure only), taking the auth
// service directly to avoid an app-package import cycle, mirroring notify.Mount.
func Mount(r chi.Router, a *auth.Service, svc *Service) {
	h := &handler{svc: svc}
	r.Group(func(pr chi.Router) {
		pr.Use(a.RequireAuth)
		pr.With(a.RequirePermission("System.Configure")).Get("/digest", h.get)
		pr.With(a.RequirePermission("System.Configure")).Put("/digest", h.put)
		pr.With(a.RequirePermission("System.Configure")).Get("/digest/preview", h.preview)
		pr.With(a.RequirePermission("System.Configure")).Post("/digest/send", h.send)
	})
}

type handler struct {
	svc *Service
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.svc.LoadPolicy(r.Context()))
}

func (h *handler) put(w http.ResponseWriter, r *http.Request) {
	var p Policy
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&p); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.svc.SavePolicy(r.Context(), p); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save digest settings")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.svc.LoadPolicy(r.Context()))
}

func (h *handler) preview(w http.ResponseWriter, r *http.Request) {
	title, body, sev, err := h.svc.Preview(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not build digest")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"title": title, "body": body, "severity": sev})
}

// send delivers a digest immediately (a "send test now" affordance). Delivery
// still depends on the fleet.digest event being routed to a channel.
func (h *handler) send(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.SendNow(r.Context()); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not send digest")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"sent": true})
}
