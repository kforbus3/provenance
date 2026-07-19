// Package system exposes operational endpoints: background-job status and
// database backup.
package system

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/jobs"
	"github.com/fleet-terminal/backend/internal/models"
)

// Mount attaches system routes (admin-gated).
func Mount(r chi.Router, d *app.Deps, reg *jobs.Registry) {
	h := &handler{d: d, reg: reg}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("System.Configure")).Get("/system/jobs", h.jobs)
		pr.With(d.Auth.RequirePermission("System.Configure")).Get("/system/backup", h.backup)
	})
}

type handler struct {
	d   *app.Deps
	reg *jobs.Registry
}

func (h *handler) jobs(w http.ResponseWriter, r *http.Request) {
	enrollJobs, err := h.d.Store.ListEnrollmentJobs(r.Context(), 50)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list enrollment jobs")
		return
	}
	if enrollJobs == nil {
		enrollJobs = []models.EnrollmentJob{}
	}
	remJobs, err := h.d.Store.ListRemediationJobs(r.Context(), 50)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list remediation jobs")
		return
	}
	// Cluster roster (High Availability): the registered backend instances and which
	// one currently holds leadership. A single-instance deployment shows one row.
	cluster, err := h.d.Store.ListClusterInstances(r.Context())
	if err != nil {
		cluster = nil // non-fatal — omit the roster rather than failing System Health
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"schedulers":      h.reg.Snapshot(),
		"enrollmentJobs":  enrollJobs,
		"remediationJobs": remJobs,
		"cluster":         cluster,
	})
}

// backup streams a logical database dump (pg_dump) as a download. Restore is an
// out-of-band operation (see the disaster-recovery guide) and is intentionally
// not exposed over the web UI.
func (h *handler) backup(w http.ResponseWriter, r *http.Request) {
	if _, err := exec.LookPath("pg_dump"); err != nil {
		httpx.WriteError(w, http.StatusNotImplemented, "pg_dump not available in this image")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	// pg_dump reads the connection URI directly; --no-owner keeps the dump portable.
	cmd := exec.CommandContext(ctx, "pg_dump", "--no-owner", "--clean", "--if-exists", h.d.Cfg.DatabaseURL)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "backup failed to start")
		return
	}
	if err := cmd.Start(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "backup failed to start")
		return
	}
	filename := fmt.Sprintf("fleet-backup-%d.sql", time.Now().Unix())
	w.Header().Set("Content-Type", "application/sql")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	_, _ = io.Copy(w, stdout)
	_ = cmd.Wait()

	p := auth.MustPrincipal(r)
	if p != nil {
		_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
			ActorID: &p.UserID, ActorName: p.Username, Action: "system.backup",
		})
	}
}
