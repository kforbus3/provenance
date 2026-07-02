// Package auditapi exposes read-only access to the tamper-evident audit log:
// listing, chain verification, and full-export streaming. All routes are gated
// by authentication plus audit permissions.
package auditapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

// Mount attaches audit routes to r, gated by authentication and permissions.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)

		pr.With(d.Auth.RequirePermission("Audit.View")).Get("/audit", h.list)
		pr.With(d.Auth.RequirePermission("Audit.View")).Get("/audit/actions", h.actions)
		pr.With(d.Auth.RequirePermission("Audit.View")).Get("/audit/verify", h.verify)
		pr.With(d.Auth.RequirePermission("Audit.Export")).Get("/audit/export", h.export)
	})
}

type handler struct{ d *app.Deps }

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	f := store.AuditFilter{
		Action:    r.URL.Query().Get("action"),
		ActorName: r.URL.Query().Get("actorName"),
		Limit:     limit,
		Offset:    offset,
	}
	// `actor` (an exact UUID) remains supported for programmatic callers; the UI
	// filters by `actorName` (substring) instead.
	if actor := r.URL.Query().Get("actor"); actor != "" {
		id, err := uuid.Parse(actor)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid actor id")
			return
		}
		f.ActorID = &id
	}
	// from/to bound created_at; accept RFC3339 timestamps.
	if from := r.URL.Query().Get("from"); from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid from timestamp (want RFC3339)")
			return
		}
		f.From = &t
	}
	if to := r.URL.Query().Get("to"); to != "" {
		t, err := time.Parse(time.RFC3339, to)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid to timestamp (want RFC3339)")
			return
		}
		f.To = &t
	}
	events, err := h.d.Store.ListAudit(r.Context(), f)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list audit events")
		return
	}
	if events == nil {
		events = []models.AuditEvent{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"events": events, "count": len(events)})
}

// actions lists the distinct action values in the log so the UI can present a
// filter dropdown rather than a free-text box.
func (h *handler) actions(w http.ResponseWriter, r *http.Request) {
	actions, err := h.d.Store.DistinctAuditActions(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list audit actions")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

func (h *handler) verify(w http.ResponseWriter, r *http.Request) {
	intact, brokenAt, err := h.d.Store.VerifyAuditChain(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not verify audit chain")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"intact": intact, "brokenAtSeq": brokenAt})
}

// export streams the entire audit log as a JSON array, paging through the store
// so the full chain can be exported without loading it all into memory at once.
func (h *handler) export(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-export.json"`)
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	_, _ = w.Write([]byte("["))
	first := true
	const page = 1000
	for offset := 0; ; offset += page {
		events, err := h.d.Store.ListAudit(r.Context(), store.AuditFilter{Limit: page, Offset: offset})
		if err != nil {
			return
		}
		for i := range events {
			if !first {
				_, _ = w.Write([]byte(","))
			}
			first = false
			_ = enc.Encode(events[i])
		}
		if len(events) < page {
			break
		}
	}
	_, _ = w.Write([]byte("]"))
}
