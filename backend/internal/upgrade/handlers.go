package upgrade

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/kforbus3/Moorgate/backend/internal/app"
	"github.com/kforbus3/Moorgate/backend/internal/auth"
	"github.com/kforbus3/Moorgate/backend/internal/httpx"
	"github.com/kforbus3/Moorgate/backend/internal/models"
)

// maxBundleBytes caps an uploaded bundle. Image bundles are large (100s of MB) but
// bounded — this stops an unbounded upload from filling the updates volume.
const maxBundleBytes = 2 << 30 // 2 GiB

type handler struct {
	d   *app.Deps
	svc *Service
}

// Mount attaches the upgrade + drain routes, all gated by System.Upgrade.
func Mount(r chi.Router, d *app.Deps, svc *Service) {
	h := &handler{d: d, svc: svc}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		up := d.Auth.RequirePermission("System.Upgrade")
		pr.With(up).Post("/system/upgrade/preview", h.preview)
		pr.With(up).Post("/system/upgrade/apply", h.apply)
		pr.With(up).Get("/system/upgrade/status", h.status)
		pr.With(up).Get("/system/upgrade/check", h.check)
		pr.With(up).Post("/system/upgrade/pull", h.pull)
		pr.With(up).Post("/system/drain", h.drain)
	})
}

// preview streams an uploaded bundle to the updates volume, verifies its signature +
// upgradeability, and returns the manifest WITHOUT applying — so the operator can
// review the version, notes, and additive/breaking flag before confirming.
func (h *handler) preview(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBundleBytes)
	file, _, err := r.FormFile("bundle")
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "expected a multipart 'bundle' file")
		return
	}
	defer file.Close()
	path, err := h.svc.Stage(file)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not stage the bundle: "+err.Error())
		return
	}
	m, err := h.svc.Verify(path)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "system.upgrade_preview", map[string]any{"version": m.Version, "migrationCompatibility": m.MigrationCompatibility})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"manifest": m})
}

// apply applies the currently-staged bundle. The client passes the previewed version
// as a guard against applying a different bundle than was reviewed.
func (h *handler) apply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Version string `json:"version"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	m, err := h.svc.Verify(h.svc.stagedPath())
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "no valid staged bundle to apply: "+err.Error())
		return
	}
	if req.Version != "" && req.Version != m.Version {
		httpx.WriteError(w, http.StatusConflict, "the staged bundle version changed since preview; re-upload and review again")
		return
	}
	p := auth.MustPrincipal(r)
	actor := ""
	if p != nil {
		actor = p.Username
	}
	h.audit(r, "system.upgrade_apply", map[string]any{"version": m.Version, "migrationCompatibility": m.MigrationCompatibility})
	// Apply runs beyond the request lifetime (it restarts the backend), so use a
	// background context; status is polled from the updater.
	go func() {
		if err := h.svc.Apply(context.Background(), h.svc.stagedPath(), actor); err != nil {
			h.svc.log.Warn("upgrade apply failed", "err", err)
		}
	}()
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"status": "applying", "version": m.Version})
}

func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.svc.Status(r.Context()))
}

// check queries the configured release channel for an available upgrade.
func (h *handler) check(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.CheckForUpdate(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "could not reach the update channel: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// pull downloads and applies a release from the channel (latest applicable if no
// version is given).
func (h *handler) pull(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Version string `json:"version"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	p := auth.MustPrincipal(r)
	actor := ""
	if p != nil {
		actor = p.Username
	}
	h.audit(r, "system.upgrade_pull", map[string]any{"version": req.Version})
	go func() {
		if err := h.svc.PullAndApply(context.Background(), req.Version, actor); err != nil {
			h.svc.log.Warn("upgrade pull failed", "err", err)
		}
	}()
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"status": "pulling", "version": req.Version})
}

func (h *handler) drain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Draining bool   `json:"draining"`
		Message  string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	msg := req.Message
	if msg == "" && req.Draining {
		msg = "Maintenance in progress — this instance is draining."
	}
	h.svc.SetDrain(req.Draining, msg)
	h.audit(r, "system.drain", map[string]any{"draining": req.Draining})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"draining": req.Draining})
}

func (h *handler) audit(r *http.Request, action string, detail map[string]any) {
	p := auth.MustPrincipal(r)
	if p == nil {
		return
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: action, Detail: detail,
	})
}
