package rdp

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
)

// MountAPI attaches the read-only RDP recording replay routes, gated by the same
// permissions as SSH session replay. The static "recordings" segment is matched
// ahead of the "/rdp/{hostId}" WebSocket route registered by Mount.
func MountAPI(r chi.Router, d *app.Deps) {
	h := &apiHandler{d: d}
	// The replay stream authenticates via a ?token= query parameter, because the
	// browser's Guacamole tunnel (an XHR) cannot set the Authorization header — the
	// same pattern as the terminal/RDP WebSocket endpoints. Registered outside the
	// Bearer-auth group.
	r.Get("/rdp/recordings/{id}/stream", h.stream)
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("Session.Replay")).Get("/rdp/recordings", h.list)
		pr.With(d.Auth.RequirePermission("Session.Replay")).Get("/rdp/recordings/stats", h.stats)
		pr.With(d.Auth.RequirePermission("Session.Replay")).Get("/rdp/recordings/{id}", h.get)
		pr.With(d.Auth.RequirePermission("Session.Replay")).Get("/rdp/recordings/{id}/download", h.download)
		pr.With(d.Auth.RequirePermission("System.Configure")).Delete("/rdp/recordings/{id}", h.remove)
		pr.With(d.Auth.RequirePermission("System.Configure")).Post("/rdp/recordings/prune", h.prune)
	})
}

type apiHandler struct{ d *app.Deps }

func (h *apiHandler) resolvePath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(h.d.Cfg.RecordingDir, p)
}

func (h *apiHandler) list(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	recs, err := h.d.Store.ListRDPRecordings(r.Context(), limit, offset)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list recordings")
		return
	}
	if recs == nil {
		recs = []*models.RDPRecording{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"recordings": recs, "count": len(recs)})
}

func (h *apiHandler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid recording id")
		return
	}
	rec, err := h.d.Store.GetRDPRecording(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "recording not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rec)
}

// stream serves the raw Guacamole recording for in-browser playback via a
// Guacamole tunnel (Guacamole.SessionRecording fed by a StaticHTTPTunnel). It
// authenticates via a ?token= query parameter since the tunnel XHR cannot set the
// Authorization header. Served as a plain-text instruction stream so the browser's
// XHR decodes it correctly (unlike the block-sliced Blob path).
func (h *apiHandler) stream(w http.ResponseWriter, r *http.Request) {
	p, err := h.d.Auth.AuthenticateToken(r.Context(), r.URL.Query().Get("token"))
	if err != nil || p == nil || !p.Has("Session.Replay") {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid recording id")
		return
	}
	rec, err := h.d.Store.GetRDPRecording(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "recording not found")
		return
	}
	f, err := os.Open(h.resolvePath(rec.Path))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "recording file not found")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.Copy(w, f)
}

// download streams the raw Guacamole recording as a file attachment (for saving a
// copy locally). In-browser playback uses stream() instead.
func (h *apiHandler) download(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid recording id")
		return
	}
	rec, err := h.d.Store.GetRDPRecording(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "recording not found")
		return
	}
	f, err := os.Open(h.resolvePath(rec.Path))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "recording file not found")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\"rdp-"+id.String()+".guac\"")
	_, _ = io.Copy(w, f)
}

func (h *apiHandler) remove(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid recording id")
		return
	}
	path, err := h.d.Store.DeleteRDPRecording(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "recording not found")
		return
	}
	_ = os.Remove(h.resolvePath(path))
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: "rdp_recording.delete",
		TargetKind: "rdp_recording", TargetID: id.String(),
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *apiHandler) prune(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	days, _ := strconv.Atoi(r.URL.Query().Get("olderThanDays"))
	if days <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "olderThanDays must be > 0")
		return
	}
	before := time.Now().AddDate(0, 0, -days)
	paths, bytes, err := h.d.Store.PruneRDPRecordingsBefore(r.Context(), before)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "prune failed")
		return
	}
	for _, path := range paths {
		_ = os.Remove(h.resolvePath(path))
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: "rdp_recording.prune",
		Detail: map[string]any{"olderThanDays": days, "deleted": len(paths), "bytesReclaimed": bytes},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": len(paths), "bytesReclaimed": bytes})
}

func (h *apiHandler) stats(w http.ResponseWriter, r *http.Request) {
	recs, err := h.d.Store.ListRDPRecordings(r.Context(), 500, 0)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "stats failed")
		return
	}
	var total int64
	for _, rec := range recs {
		total += rec.SizeBytes
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"count": len(recs), "bytes": total})
}
