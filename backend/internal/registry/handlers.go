package registry

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/store"
)

type handler struct {
	d   *app.Deps
	svc *Checker
	st  *store.Store
}

// Mount attaches container-image update routes.
//
// Host.Scan, matching the container vulnerability scans these sit beside: both
// answer "what is wrong with what this host is running", and an operator who can
// see one has no reason to be denied the other. Triggering a check is a read of
// public registries, not a change to any host, so it needs nothing more.
func Mount(r chi.Router, d *app.Deps, svc *Checker, st *store.Store) {
	h := &handler{d: d, svc: svc, st: st}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/container-updates", h.list)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Post("/container-updates/check", h.check)
	})
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.st.ImageUpdatesWithHosts(r.Context())
	if err != nil {
		h.d.Log.Warn("listing container updates", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not list container updates")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"updates": rows})
}

func (h *handler) check(w http.ResponseWriter, r *http.Request) {
	// Detached from the request: a sweep over every image the fleet runs takes
	// longer than the 60s router timeout, and cancelling it halfway would leave
	// half the table updated with no record of why the rest was skipped.
	ctx := context.WithoutCancel(r.Context())
	go func() {
		checked, failed := h.svc.Check(ctx)
		h.d.Log.Info("container update check (manual)", "checked", checked, "failed", failed)
	}()
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"status": "checking",
		"note":   "results appear as each registry answers; refresh to see them",
	})
}
