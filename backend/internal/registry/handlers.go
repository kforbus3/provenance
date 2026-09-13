package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

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

// selfProject is the compose project that is this application. Its containers are
// shown but never offered for a rollout — this application is upgraded by signed
// bundle. See internal/containerupdate/selfprotect.go.
func (h *handler) selfProject(ctx context.Context) string {
	if raw, err := h.st.GetSetting(ctx, "containers.selfProject"); err == nil && len(raw) > 0 {
		var v string
		if json.Unmarshal(raw, &v) == nil && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return "provenance"
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
	rows, err := h.st.ImageUpdatesWithHosts(r.Context(), h.selfProject(r.Context()))
	if err != nil {
		h.d.Log.Warn("listing container updates", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not list container updates")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"updates": rows})
}

func (h *handler) check(w http.ResponseWriter, r *http.Request) {
	// A deliberate press means now.
	//
	// The twelve-hour window exists to stop the scheduled sweep re-asking
	// registries about answers it already has. Applying it to somebody who has
	// just pressed a button made the button do nothing whenever it was most
	// wanted — after changing something and wanting to see the effect.
	//
	// Opt out with ?force=0 for a pass that respects the window, which is what a
	// script polling this endpoint should do.
	force := r.URL.Query().Get("force") != "0"

	// Detached from the request: a sweep over every image the fleet runs takes
	// longer than the 60s router timeout, and cancelling it halfway would leave
	// half the table updated with no record of why the rest was skipped.
	ctx := context.WithoutCancel(r.Context())
	go func() {
		var checked, failed, remaining int
		if force {
			checked, failed, remaining = h.svc.CheckNow(ctx)
		} else {
			checked, failed = h.svc.Check(ctx)
		}
		h.d.Log.Info("container update check (manual)",
			"checked", checked, "failed", failed, "forced", force, "remaining", remaining)
	}()

	note := "results appear as each registry answers; refresh to see them"
	if force {
		note = "re-asking every registry, ignoring the twelve-hour freshness window — results appear as each answers"
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"status": "checking", "note": note})
}
