package reportsched

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
)

// Mount attaches report-schedule settings routes (System.Configure only).
func Mount(r chi.Router, a *auth.Service, svc *Service) {
	h := &handler{svc: svc}
	r.Group(func(pr chi.Router) {
		pr.Use(a.RequireAuth)
		pr.With(a.RequirePermission("System.Configure")).Get("/report-schedule", h.get)
		pr.With(a.RequirePermission("System.Configure")).Put("/report-schedule", h.put)
		pr.With(a.RequirePermission("System.Configure")).Post("/report-schedule/send", h.send)
	})
}

type handler struct{ svc *Service }

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
		httpx.WriteError(w, http.StatusInternalServerError, "could not save report schedule")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.svc.LoadPolicy(r.Context()))
}

// send delivers the configured reports immediately (a "send now" affordance).
// Delivery still depends on the report.scheduled event being routed to a channel.
func (h *handler) send(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.SendNow(r.Context()); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not send reports")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"sent": true})
}
