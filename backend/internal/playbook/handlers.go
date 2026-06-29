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
		// Execution requires Playbook.Run (admin-only by default) and host access.
		pr.With(d.Auth.RequirePermission("Playbook.Run")).Post("/playbooks/{id}/run", h.run)
		pr.With(d.Auth.RequirePermission("Playbook.Run")).Get("/playbooks/{id}/runs", h.runs)
		pr.With(d.Auth.RequirePermission("Playbook.Run")).Get("/playbook-runs/{runId}", h.runStatus)
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

// --- execution (Playbook.Run) ---

type runReq struct {
	TargetKind string `json:"targetKind"` // host (group arrives in Phase 3)
	TargetID   string `json:"targetId"`
	CheckMode  bool   `json:"checkMode"`
}

func (h *handler) run(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	pb, err := h.d.Store.GetPlaybook(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "playbook not found")
		return
	}
	var rq runReq
	if !decode(w, r, &rq) {
		return
	}
	if rq.TargetKind == "" {
		rq.TargetKind = "host"
	}
	if rq.TargetKind != "host" {
		writeError(w, http.StatusBadRequest, "only single-host runs are supported")
		return
	}
	hostID, err := uuid.Parse(rq.TargetID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad target id")
		return
	}
	host, err := h.d.Store.GetHost(r.Context(), hostID)
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	p := auth.MustPrincipal(r)
	if !h.canAccessHost(r, p, host.ID) {
		writeError(w, http.StatusForbidden, "not authorized for host")
		return
	}

	rec, err := h.d.Store.CreatePlaybookRun(r.Context(), models.PlaybookRun{
		PlaybookID:      pb.ID,
		PlaybookVersion: pb.Version,
		Requester:       p.Username,
		TargetKind:      "host",
		TargetID:        &host.ID,
		TargetName:      host.Hostname,
		HostCount:       1,
		CheckMode:       rq.CheckMode,
	}, &p.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create run")
		return
	}
	go h.svc.Run(rec.ID, pb.Content, []*models.Host{host}, rq.CheckMode)

	h.audit(r, "playbook.run", pb.ID.String(), map[string]any{
		"name": pb.Name, "version": pb.Version, "runId": rec.ID,
		"hostId": host.ID, "hostname": host.Hostname, "checkMode": rq.CheckMode,
	})
	writeJSON(w, http.StatusAccepted, rec)
}

func (h *handler) runs(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	rs, err := h.d.Store.ListPlaybookRuns(r.Context(), id, 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list runs")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": rs, "count": len(rs)})
}

func (h *handler) runStatus(w http.ResponseWriter, r *http.Request) {
	runID, err := uuid.Parse(chi.URLParam(r, "runId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad run id")
		return
	}
	rec, err := h.d.Store.GetPlaybookRun(r.Context(), runID)
	if err != nil {
		writeError(w, http.StatusNotFound, "run not found")
		return
	}
	// While running, the persisted output is empty; serve the live buffer so the
	// browser sees output stream in by polling.
	if out, live := h.svc.LiveOutput(runID); live {
		rec.Output = out
	}
	writeJSON(w, http.StatusOK, rec)
}

// canAccessHost mirrors the scan/terminal gate: super admins bypass; otherwise
// the user must have access to the host (group/direct/temporary).
func (h *handler) canAccessHost(r *http.Request, p *auth.Principal, hostID uuid.UUID) bool {
	if p == nil {
		return false
	}
	if p.IsSuperAdmin {
		return true
	}
	ok, err := h.d.Store.UserCanAccessHost(r.Context(), p.UserID, hostID)
	return err == nil && ok
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
