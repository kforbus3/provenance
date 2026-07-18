// Package accessreview exposes access-certification campaigns: snapshot the
// current access grants, keep or revoke each, and produce evidence. All routes
// require AccessReview.Manage.
package accessreview

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
)

func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(d.Auth.RequirePermission("AccessReview.Manage"))
		pr.Get("/access-reviews", h.list)
		pr.Post("/access-reviews", h.create)
		pr.Get("/access-reviews/{id}", h.get)
		pr.Get("/access-reviews/{id}/export.csv", h.export)
		pr.Post("/access-reviews/{id}/complete", h.complete)
		pr.Post("/access-reviews/{id}/items/{itemId}/decide", h.decide)
	})
}

type handler struct{ d *app.Deps }

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	rv, err := h.d.Store.ListAccessReviews(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list reviews")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"reviews": rv})
}

type createReq struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Scope       models.ReviewScope `json:"scope"`
	DueInDays   int                `json:"dueInDays"`
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var rq createReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&rq); err != nil || rq.Name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	if rq.Scope.Type == "" {
		rq.Scope.Type = "all"
	}
	var due *time.Time
	if rq.DueInDays > 0 {
		t := time.Now().Add(time.Duration(rq.DueInDays) * 24 * time.Hour)
		due = &t
	}
	p := auth.MustPrincipal(r)
	rv, err := h.d.Store.CreateAccessReview(r.Context(), rq.Name, rq.Description, rq.Scope, p.UserID, due)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "could not create review: "+err.Error())
		return
	}
	h.audit(r, "access_review.create", rv.ID, map[string]any{"name": rv.Name, "items": rv.Total})
	httpx.WriteJSON(w, http.StatusCreated, rv)
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	rv, err := h.d.Store.GetAccessReview(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such review")
		return
	}
	items, err := h.d.Store.AccessReviewItems(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not load items")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"review": rv, "items": items})
}

type decideReq struct {
	Decision string `json:"decision"` // keep | revoke
	Note     string `json:"note"`
}

func (h *handler) decide(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	itemID, ok := parseID(w, r, "itemId")
	if !ok {
		return
	}
	var rq decideReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := auth.MustPrincipal(r)
	if err := h.d.Store.DecideReviewItem(r.Context(), id, itemID, p.UserID, rq.Decision, rq.Note); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "could not record decision: "+err.Error())
		return
	}
	if rq.Decision == "revoke" {
		h.audit(r, "access_review.revoke", id, map[string]any{"item": itemID.String()})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *handler) complete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	p := auth.MustPrincipal(r)
	if err := h.d.Store.CompleteAccessReview(r.Context(), id, p.UserID); err != nil {
		httpx.WriteError(w, http.StatusConflict, "could not complete review")
		return
	}
	h.audit(r, "access_review.complete", id, nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "completed"})
}

func (h *handler) export(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	table, err := h.d.Store.ExportAccessReview(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not build export")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="access-review-`+id.String()+`.csv"`)
	_, _ = w.Write(table.CSVBytes())
}

func (h *handler) audit(r *http.Request, action string, target uuid.UUID, detail map[string]any) {
	p := auth.MustPrincipal(r)
	if detail == nil {
		detail = map[string]any{}
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: action, TargetKind: "access_review",
		TargetID: target.String(), Detail: detail,
	})
}

func parseID(w http.ResponseWriter, r *http.Request, key string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, key))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return uuid.Nil, false
	}
	return id, true
}
