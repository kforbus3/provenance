package backup

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/models"
)

// Mount attaches backup routes (System.Configure only). The encrypted download
// uses a token query param so the browser can fetch it directly.
func Mount(r chi.Router, d *app.Deps, svc *Service) {
	h := &handler{d: d, svc: svc}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("System.Configure")).Get("/system/backups", h.list)
		pr.With(d.Auth.RequirePermission("System.Configure")).Post("/system/backups", h.create)
		pr.With(d.Auth.RequirePermission("System.Configure")).Get("/system/backup-policy", h.getPolicy)
		pr.With(d.Auth.RequirePermission("System.Configure")).Put("/system/backup-policy", h.putPolicy)
	})
	// Download authenticates via token query param (browser navigation).
	r.Get("/system/backups/{name}", h.download)
}

type handler struct {
	d   *app.Deps
	svc *Service
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	items, err := h.svc.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list backups")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"backups": items, "dir": h.d.Cfg.BackupDir, "count": len(items),
	})
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	info, err := h.svc.Create(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "system.backup", map[string]any{"name": info.Name, "size": info.Size})
	writeJSON(w, http.StatusCreated, info)
}

func (h *handler) getPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.svc.LoadPolicy(r.Context()))
}

func (h *handler) putPolicy(w http.ResponseWriter, r *http.Request) {
	var p Policy
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.svc.SavePolicy(r.Context(), p); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save policy")
		return
	}
	h.audit(r, "system.backup_policy", map[string]any{"enabled": p.Enabled, "intervalHours": p.IntervalHours})
	writeJSON(w, http.StatusOK, p)
}

func (h *handler) download(w http.ResponseWriter, r *http.Request) {
	principal, err := h.d.Auth.AuthenticateToken(r.Context(), r.URL.Query().Get("token"))
	if err != nil || !principal.Has("System.Configure") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := chi.URLParam(r, "name")
	rc, size, err := h.svc.Open(name)
	if err != nil {
		http.Error(w, "backup not found", http.StatusNotFound)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	_, _ = io.Copy(w, rc)
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
