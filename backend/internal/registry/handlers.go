package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/stateful"
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
	markMigrations(rows)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"updates": rows})
}

// markMigrations re-labels an "update" that a rollout can never apply.
//
// A major-version bump of a stateful image is refused when a rollout is started,
// which was the whole guard -- and it left two rows on this page reading like
// ordinary updates forever. That is not cosmetic:
//
//   - the summary counts them, so the number of things "available" never reaches
//     zero no matter what the operator does;
//   - "roll out everything" includes them, and the refusal rejects the WHOLE
//     request, so one impossible row blocks every real update behind it.
//
// Saying it here, where the list is read, is what lets the page leave them out of
// the count and out of the selection. The refusal at rollout time stays as the last
// line of defence, because this annotation is advice and that one is a gate.
func markMigrations(rows []store.ImageUpdateRow) {
	for i := range rows {
		r := &rows[i]
		if r.Status != "update" || r.LatestTag == "" {
			continue
		}
		how, yes := stateful.MajorBump(r.Repository, r.Tag, r.LatestTag)
		if !yes {
			continue
		}
		r.Status = "migration"
		r.Note = r.LatestTag + " crosses a major version of an image that owns its on-disk " +
			"format. The new version will refuse the existing data directory and the container " +
			"will restart with the service down. It needs " + how + " first, with both versions " +
			"available — which a container rollout cannot do."
	}
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
