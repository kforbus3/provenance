package insights

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
)

// Mount attaches the insights endpoint. Results are scoped to the caller's
// accessible hosts, so plain authentication is sufficient.
func Mount(r chi.Router, d *app.Deps, svc *Service) {
	h := &handler{svc: svc}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Get("/insights", h.list)
	})
}

type handler struct {
	svc *Service
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	items, err := h.svc.Compute(r.Context(), p.UserID, p.IsSuperAdmin)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not compute insights")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"insights": items})
}
