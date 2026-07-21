// Package sessionsapi exposes read-only access to recorded SSH sessions and
// their replay recordings. All routes are gated by authentication plus the
// Session.Replay permission.
package sessionsapi

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
	"github.com/fleet-terminal/backend/internal/store"
)

// Mount attaches session routes to r, gated by authentication and permissions.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)

		pr.With(d.Auth.RequirePermission("Session.Replay")).Get("/sessions", h.list)
		pr.With(d.Auth.RequirePermission("Session.Replay")).Get("/sessions/search", h.search)
		pr.With(d.Auth.RequirePermission("Session.Replay")).Get("/session-commands", h.commandSearch)
		pr.With(d.Auth.RequirePermission("Session.Replay")).Get("/sessions/{id}", h.get)
		pr.With(d.Auth.RequirePermission("Session.Replay")).Get("/sessions/{id}/recording", h.recording)
		pr.With(d.Auth.RequirePermission("Session.Replay")).Get("/sessions/{id}/recording/download", h.downloadRecording)
		pr.With(d.Auth.RequirePermission("Session.Replay")).Get("/sessions/{id}/recording/player", h.playerRecording)
		// Deleting/pruning recordings is a retention/admin action.
		pr.With(d.Auth.RequirePermission("System.Configure")).Delete("/sessions/{id}/recording", h.deleteRecording)
		pr.With(d.Auth.RequirePermission("System.Configure")).Post("/recordings/prune", h.prune)
		pr.With(d.Auth.RequirePermission("Session.Replay")).Get("/recordings/stats", h.stats)
	})
}

func (h *handler) resolvePath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(h.d.Cfg.RecordingDir, p)
}

type handler struct{ d *app.Deps }

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	f := store.SSHSessionFilter{Limit: limit, Offset: offset}
	if user := r.URL.Query().Get("user"); user != "" {
		id, err := uuid.Parse(user)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
			return
		}
		f.UserID = &id
	}
	if host := r.URL.Query().Get("host"); host != "" {
		id, err := uuid.Parse(host)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
			return
		}
		f.HostID = &id
	}
	sessions, err := h.d.Store.ListSSHSessions(r.Context(), f)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list sessions")
		return
	}
	if sessions == nil {
		sessions = []models.SSHSession{}
	}
	// Flag which sessions actually have a recording so the UI only offers
	// export/replay/delete for those.
	if withRec, rerr := h.d.Store.RecordingSessionIDs(r.Context()); rerr == nil {
		for i := range sessions {
			sessions[i].HasRecording = withRec[sessions[i].ID]
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"sessions": sessions, "count": len(sessions)})
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	sess, err := h.d.Store.GetSSHSession(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "session not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sess)
}

func (h *handler) recording(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	rec, err := h.d.Store.GetRecordingBySession(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "recording not found")
		return
	}
	// Resolve the on-disk path; relative paths are taken under the configured
	// recording directory.
	path := rec.Path
	if !filepath.IsAbs(path) {
		path = filepath.Join(h.d.Cfg.RecordingDir, path)
	}
	cast, err := os.ReadFile(path)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "recording file not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"recording": rec, "cast": string(cast)})
}

// downloadRecording streams the asciicast file as a download (export).
func (h *handler) downloadRecording(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	rec, err := h.d.Store.GetRecordingBySession(r.Context(), id)
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
	w.Header().Set("Content-Type", "application/x-asciicast")
	w.Header().Set("Content-Disposition", "attachment; filename=\"session-"+id.String()+".cast\"")
	_, _ = io.Copy(w, f)
}

// playerRecording returns a fully self-contained HTML document that plays the
// recording offline (player bundle + cast inlined). The client downloads it.
func (h *handler) playerRecording(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	rec, err := h.d.Store.GetRecordingBySession(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "recording not found")
		return
	}
	cast, err := os.ReadFile(h.resolvePath(rec.Path))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "recording file not found")
		return
	}
	sess, _ := h.d.Store.GetSSHSession(r.Context(), id)
	title := "Fleet Terminal session"
	if sess != nil {
		title = sess.Username + "@" + sess.Hostname + " · " + sess.StartedAt.Format("2006-01-02 15:04:05")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, renderPlayerHTML(title, string(cast)))
}

// deleteRecording removes a session's recording (DB row + file).
func (h *handler) deleteRecording(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	path, err := h.d.Store.DeleteRecordingBySession(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "recording not found")
		return
	}
	_ = os.Remove(h.resolvePath(path))
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: "recording.delete",
		TargetKind: "session", TargetID: id.String(),
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// prune deletes recordings older than the given number of days (retention).
func (h *handler) prune(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	days, _ := strconv.Atoi(r.URL.Query().Get("olderThanDays"))
	if days <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "olderThanDays must be > 0")
		return
	}
	before := time.Now().AddDate(0, 0, -days)
	paths, bytes, err := h.d.Store.PruneRecordingsBefore(r.Context(), before)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "prune failed")
		return
	}
	for _, path := range paths {
		_ = os.Remove(h.resolvePath(path))
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: "recording.prune",
		Detail: map[string]any{"olderThanDays": days, "deleted": len(paths), "bytesReclaimed": bytes},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": len(paths), "bytesReclaimed": bytes})
}

// stats reports recording count and total storage.
func (h *handler) stats(w http.ResponseWriter, r *http.Request) {
	count, total, err := h.d.Store.RecordingsStorageBytes(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "stats failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"count": count, "bytes": total})
}
