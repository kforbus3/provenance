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

	"github.com/kforbus3/Moorgate/backend/internal/app"
	"github.com/kforbus3/Moorgate/backend/internal/httpx"
	"github.com/kforbus3/Moorgate/backend/internal/models"
	"github.com/kforbus3/Moorgate/backend/internal/store"
	"github.com/kforbus3/Moorgate/backend/internal/tenant"
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

// enrichApprovalEvents fills in the requester + target resource on approval-
// targeted audit events, resolved from the approval request that still exists in
// the DB. This makes older events (recorded before the detail was captured
// inline) readable — "approval:<uuid>" alone doesn't say who or what. It only
// fills missing keys, so newer events that already carry the detail are untouched.
// Display-only: it mutates the response copy, never the hash-chained rows.
func enrichApprovalEvents(r *http.Request, h *handler, events []models.AuditEvent) {
	var ids []uuid.UUID
	for _, e := range events {
		if e.TargetKind == "approval" {
			if id, err := uuid.Parse(e.TargetID); err == nil {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return
	}
	summ, err := h.d.Store.ApprovalSummaries(r.Context(), ids)
	if err != nil {
		return
	}
	put := func(m map[string]any, k, v string) {
		if v == "" {
			return
		}
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}
	for i := range events {
		if events[i].TargetKind != "approval" {
			continue
		}
		id, err := uuid.Parse(events[i].TargetID)
		if err != nil {
			continue
		}
		ar, ok := summ[id]
		if !ok {
			continue // request row was deleted; nothing to resolve
		}
		if events[i].Detail == nil {
			events[i].Detail = map[string]any{}
		}
		put(events[i].Detail, "requester", ar.Requester)
		put(events[i].Detail, "targetKind", ar.TargetKind)
		put(events[i].Detail, "targetName", ar.TargetName)
	}
}

// enrichEntityEvents resolves user and host UUIDs — in an event's target and in
// its detail values — to their usernames and hostnames, so the audit log reads
// "user: alice · hostId: web-01" instead of bare UUIDs. It sets TargetName for a
// user/host target and rewrites any detail value that is a UUID naming a known
// user or host. Display-only: it mutates the response copy fetched for the UI,
// never the hash-chained rows (and is not applied to the machine-readable export).
func enrichEntityEvents(r *http.Request, h *handler, events []models.AuditEvent) {
	// Collect every UUID referenced: the target id and any UUID-valued detail entry.
	seen := map[uuid.UUID]bool{}
	add := func(s string) {
		if id, err := uuid.Parse(s); err == nil {
			seen[id] = true
		}
	}
	for i := range events {
		add(events[i].TargetID)
		for _, v := range events[i].Detail {
			if s, ok := v.(string); ok {
				add(s)
			}
		}
	}
	if len(seen) == 0 {
		return
	}
	ids := make([]uuid.UUID, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	users, _ := h.d.Store.UsernamesByIDs(r.Context(), ids)
	hosts, _ := h.d.Store.HostnamesByIDs(r.Context(), ids)
	// name resolves a UUID to a display name, preferring a user then a host.
	name := func(s string) string {
		id, err := uuid.Parse(s)
		if err != nil {
			return ""
		}
		if n, ok := users[id]; ok {
			return n
		}
		if n, ok := hosts[id]; ok {
			return n
		}
		return ""
	}
	applyEntityNames(events, name)
}

// applyEntityNames is the pure rewrite step of enrichEntityEvents: it sets a
// user/host target's TargetName and replaces UUID-valued detail entries with the
// name `resolve` returns (empty string = leave as-is). Split out so it is testable
// without a database.
func applyEntityNames(events []models.AuditEvent, resolve func(string) string) {
	for i := range events {
		if events[i].TargetName == "" {
			if n := resolve(events[i].TargetID); n != "" {
				events[i].TargetName = n
			}
		}
		for k, v := range events[i].Detail {
			if s, ok := v.(string); ok {
				if n := resolve(s); n != "" {
					//nolint:gosec // i is the index from `for i := range events`, always in bounds; Detail[k] is a map write to an existing key
					events[i].Detail[k] = n
				}
			}
		}
	}
}

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
	enrichApprovalEvents(r, h, events)
	enrichEntityEvents(r, h, events)
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
	// Verify under bypass: the hash chain is a single global sequence across all
	// tenants, so a tenant-scoped read would hide rows and falsely report a break.
	intact, brokenAt, err := h.d.Store.VerifyAuditChain(tenant.WithBypass(r.Context()))
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
