package playbook

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/models"
)

// Mount attaches playbook routes. Authoring + validation require Playbook.Edit
// (Administrator-only by default); execution routes (Playbook.Run) arrive in
// Phase 2.
func Mount(r chi.Router, d *app.Deps, svc *Service) {
	h := &handler{d: d, svc: svc}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("Playbook.Edit")).Get("/playbooks", h.list)
		pr.With(d.Auth.RequirePermission("Playbook.Edit")).Post("/playbooks", h.create)
		pr.With(d.Auth.RequirePermission("Playbook.Edit")).Get("/playbooks/runner", h.runnerStatus)
		pr.With(d.Auth.RequirePermission("Playbook.Edit")).Post("/playbooks/validate", h.validate)
		pr.With(d.Auth.RequirePermission("Playbook.Edit")).Post("/playbooks/lint", h.lint)
		pr.With(d.Auth.RequirePermission("Playbook.Edit")).Get("/playbooks/{id}", h.get)
		pr.With(d.Auth.RequirePermission("Playbook.Edit")).Put("/playbooks/{id}", h.update)
		pr.With(d.Auth.RequirePermission("Playbook.Edit")).Delete("/playbooks/{id}", h.delete)
		pr.With(d.Auth.RequirePermission("Playbook.Edit")).Get("/playbooks/{id}/versions", h.versions)
		pr.With(d.Auth.RequirePermission("Playbook.Edit")).Get("/playbooks/{id}/versions/{version}", h.version)
	})
}

type handler struct {
	d   *app.Deps
	svc *Service
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	pbs, err := h.d.Store.ListPlaybooks(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list playbooks")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"playbooks": pbs, "count": len(pbs)})
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	pb, err := h.d.Store.GetPlaybook(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "playbook not found")
		return
	}
	writeJSON(w, http.StatusOK, pb)
}

type writeReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Content     string `json:"content"`
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var rq writeReq
	if !decode(w, r, &rq) {
		return
	}
	rq.Name = strings.TrimSpace(rq.Name)
	if rq.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	p := auth.MustPrincipal(r)
	pb, err := h.d.Store.CreatePlaybook(r.Context(), rq.Name, rq.Description, rq.Content, &p.UserID, p.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create playbook")
		return
	}
	h.audit(r, "playbook.create", pb.ID.String(), map[string]any{"name": pb.Name})
	writeJSON(w, http.StatusCreated, pb)
}

func (h *handler) update(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var rq writeReq
	if !decode(w, r, &rq) {
		return
	}
	rq.Name = strings.TrimSpace(rq.Name)
	if rq.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	p := auth.MustPrincipal(r)
	pb, err := h.d.Store.UpdatePlaybook(r.Context(), id, rq.Name, rq.Description, rq.Content, &p.UserID, p.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update playbook")
		return
	}
	h.audit(r, "playbook.update", pb.ID.String(), map[string]any{"name": pb.Name, "version": pb.Version})
	writeJSON(w, http.StatusOK, pb)
}

func (h *handler) delete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := h.d.Store.DeletePlaybook(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "playbook not found")
		return
	}
	h.audit(r, "playbook.delete", id.String(), nil)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (h *handler) versions(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	vs, err := h.d.Store.ListPlaybookVersions(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list versions")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": vs, "count": len(vs)})
}

func (h *handler) version(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	n, err := strconv.Atoi(chi.URLParam(r, "version"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad version")
		return
	}
	v, err := h.d.Store.GetPlaybookVersion(r.Context(), id, n)
	if err != nil {
		writeError(w, http.StatusNotFound, "version not found")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

type contentReq struct {
	Content string `json:"content"`
}

func (h *handler) validate(w http.ResponseWriter, r *http.Request) {
	var rq contentReq
	if !decode(w, r, &rq) {
		return
	}
	res, err := h.svc.SyntaxCheck(r.Context(), rq.Content)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *handler) lint(w http.ResponseWriter, r *http.Request) {
	var rq contentReq
	if !decode(w, r, &rq) {
		return
	}
	res, err := h.svc.Lint(r.Context(), rq.Content)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *handler) runnerStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"available": h.svc.Healthy(r.Context())})
}

// --- helpers ---

func parseID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad playbook id")
		return uuid.Nil, false
	}
	return id, true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

func (h *handler) audit(r *http.Request, action, targetID string, detail map[string]any) {
	p := auth.MustPrincipal(r)
	var actorID *uuid.UUID
	var name string
	if p != nil {
		actorID = &p.UserID
		name = p.Username
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: actorID, ActorName: name, Action: action,
		TargetKind: "playbook", TargetID: targetID, Detail: detail,
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
