package support

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
)

// Mount attaches the support-bundle route. Needs Host.Scan plus access to the
// host (the same privileged-diagnostics gate as scans; super admins bypass).
func Mount(r chi.Router, d *app.Deps, svc *Service) {
	h := &handler{d: d, svc: svc}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/hosts/{id}/support-bundle", h.bundle)
	})
}

type handler struct {
	d   *app.Deps
	svc *Service
}

func (h *handler) bundle(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad host id")
		return
	}
	host, err := h.d.Store.GetHost(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "host not found")
		return
	}
	p := auth.MustPrincipal(r)
	if p == nil || (!p.IsSuperAdmin && !canAccess(h, r, p.UserID, host.ID)) {
		httpx.WriteError(w, http.StatusForbidden, "not authorized for host")
		return
	}

	// Collect to a temp file first so a mid-stream failure returns a clean error
	// instead of a truncated download.
	tmp, err := os.CreateTemp("", "fleet-support-*.tgz")
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not stage bundle")
		return
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	if err := h.svc.Collect(ctx, host, tmp); err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "could not collect support bundle: "+err.Error())
		return
	}

	httpx.Audit(r, h.d.Store, models.AuditEvent{
		Action: "host.support_bundle", TargetKind: "host", TargetID: host.ID.String(),
		Detail: map[string]any{"hostname": host.Hostname},
	})

	fi, _ := tmp.Stat()
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read bundle")
		return
	}
	name := fmt.Sprintf("%s-support-%s.tar.gz", host.Hostname, time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	if fi != nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
	}
	_, _ = io.Copy(w, tmp)
}

func canAccess(h *handler, r *http.Request, userID, hostID uuid.UUID) bool {
	ok, err := h.d.Store.UserCanAccessHost(r.Context(), userID, hostID)
	return err == nil && ok
}
