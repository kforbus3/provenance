package playbook

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
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
		httpx.WriteError(w, http.StatusInternalServerError, "could not list playbooks")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"playbooks": pbs, "count": len(pbs)})
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseID(w, r)
	if !ok {
		return
	}
	pb, err := h.d.Store.GetPlaybook(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "playbook not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pb)
}

type writeReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Content     string `json:"content"`
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var rq writeReq
	if !httpx.Decode(w, r, &rq) {
		return
	}
	rq.Name = strings.TrimSpace(rq.Name)
	if rq.Name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	p := auth.MustPrincipal(r)
	pb, err := h.d.Store.CreatePlaybook(r.Context(), rq.Name, rq.Description, rq.Content, &p.UserID, p.Username)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create playbook")
		return
	}
	h.audit(r, "playbook.create", pb.ID.String(), map[string]any{"name": pb.Name})
	httpx.WriteJSON(w, http.StatusCreated, pb)
}

func (h *handler) update(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseID(w, r)
	if !ok {
		return
	}
	var rq writeReq
	if !httpx.Decode(w, r, &rq) {
		return
	}
	rq.Name = strings.TrimSpace(rq.Name)
	if rq.Name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	p := auth.MustPrincipal(r)
	pb, err := h.d.Store.UpdatePlaybook(r.Context(), id, rq.Name, rq.Description, rq.Content, &p.UserID, p.Username)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update playbook")
		return
	}
	h.audit(r, "playbook.update", pb.ID.String(), map[string]any{"name": pb.Name, "version": pb.Version})
	httpx.WriteJSON(w, http.StatusOK, pb)
}

func (h *handler) delete(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseID(w, r)
	if !ok {
		return
	}
	if err := h.d.Store.DeletePlaybook(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "playbook not found")
		return
	}
	h.audit(r, "playbook.delete", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (h *handler) versions(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseID(w, r)
	if !ok {
		return
	}
	vs, err := h.d.Store.ListPlaybookVersions(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list versions")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"versions": vs, "count": len(vs)})
}

func (h *handler) version(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseID(w, r)
	if !ok {
		return
	}
	n, err := strconv.Atoi(chi.URLParam(r, "version"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad version")
		return
	}
	v, err := h.d.Store.GetPlaybookVersion(r.Context(), id, n)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "version not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

type contentReq struct {
	Content string `json:"content"`
}

func (h *handler) validate(w http.ResponseWriter, r *http.Request) {
	var rq contentReq
	if !httpx.Decode(w, r, &rq) {
		return
	}
	res, err := h.svc.SyntaxCheck(r.Context(), rq.Content)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *handler) lint(w http.ResponseWriter, r *http.Request) {
	var rq contentReq
	if !httpx.Decode(w, r, &rq) {
		return
	}
	res, err := h.svc.Lint(r.Context(), rq.Content)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *handler) runnerStatus(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"available": h.svc.Healthy(r.Context())})
}

// --- execution (Playbook.Run) ---

type runReq struct {
	TargetKind string   `json:"targetKind"` // host | group
	HostIDs    []string `json:"hostIds"`    // when targetKind=host (one or many)
	GroupID    string   `json:"groupId"`    // when targetKind=group
	TargetID   string   `json:"targetId"`   // back-compat: a single host id
	CheckMode  bool     `json:"checkMode"`
}

func (h *handler) run(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseID(w, r)
	if !ok {
		return
	}
	pb, err := h.d.Store.GetPlaybook(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "playbook not found")
		return
	}
	var rq runReq
	if !httpx.Decode(w, r, &rq) {
		return
	}
	if rq.TargetKind == "" {
		rq.TargetKind = "host"
	}
	p := auth.MustPrincipal(r)

	var (
		hosts      []*models.Host
		targetKind = rq.TargetKind
		targetName string
		groupID    *uuid.UUID
	)

	switch rq.TargetKind {
	case "host":
		// Accept either an explicit list (hostIds) or a single targetId.
		ids := rq.HostIDs
		if len(ids) == 0 && rq.TargetID != "" {
			ids = []string{rq.TargetID}
		}
		if len(ids) == 0 {
			httpx.WriteError(w, http.StatusBadRequest, "no target hosts")
			return
		}
		seen := map[uuid.UUID]bool{}
		for _, raw := range ids {
			hid, err := uuid.Parse(raw)
			if err != nil {
				httpx.WriteError(w, http.StatusBadRequest, "bad host id")
				return
			}
			if seen[hid] {
				continue
			}
			seen[hid] = true
			host, err := h.d.Store.GetHost(r.Context(), hid)
			if err != nil {
				httpx.WriteError(w, http.StatusNotFound, "host not found")
				return
			}
			if !h.canAccessHost(r, p, host.ID) {
				httpx.WriteError(w, http.StatusForbidden, "not authorized for host "+host.Hostname)
				return
			}
			hosts = append(hosts, host)
		}
		if len(hosts) == 1 {
			targetName = hosts[0].Hostname
		} else {
			targetName = fmt.Sprintf("%d hosts", len(hosts))
		}

	case "group":
		gid, err := uuid.Parse(rq.GroupID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "bad group id")
			return
		}
		g, err := h.d.Store.GetGroup(r.Context(), gid)
		if err != nil {
			httpx.WriteError(w, http.StatusNotFound, "group not found")
			return
		}
		members, err := h.d.Store.HostsInGroup(r.Context(), gid)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not resolve group hosts")
			return
		}
		// Only target hosts the requester can actually reach (super admins: all).
		for i := range members {
			m := members[i]
			if h.canAccessHost(r, p, m.ID) {
				hosts = append(hosts, &m)
			}
		}
		if len(hosts) == 0 {
			httpx.WriteError(w, http.StatusForbidden, "no hosts in this group are accessible to you")
			return
		}
		groupID = &g.ID
		targetName = g.Name

	default:
		httpx.WriteError(w, http.StatusBadRequest, "unknown target kind")
		return
	}

	var targetID *uuid.UUID
	switch {
	case targetKind == "group":
		targetID = groupID
	case len(hosts) == 1:
		targetID = &hosts[0].ID
	}

	rec, err := h.d.Store.CreatePlaybookRun(r.Context(), models.PlaybookRun{
		PlaybookID:      pb.ID,
		PlaybookVersion: pb.Version,
		Requester:       p.Username,
		TargetKind:      targetKind,
		TargetID:        targetID,
		TargetName:      targetName,
		HostCount:       len(hosts),
		CheckMode:       rq.CheckMode,
	}, &p.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create run")
		return
	}
	go h.svc.Run(rec.ID, pb.Content, hosts, rq.CheckMode)

	names := make([]string, 0, len(hosts))
	for _, hh := range hosts {
		names = append(names, hh.Hostname)
	}
	h.audit(r, "playbook.run", pb.ID.String(), map[string]any{
		"name": pb.Name, "version": pb.Version, "runId": rec.ID,
		"targetKind": targetKind, "target": targetName, "hosts": names,
		"hostCount": len(hosts), "checkMode": rq.CheckMode,
	})
	httpx.WriteJSON(w, http.StatusAccepted, rec)
}

func (h *handler) runs(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseID(w, r)
	if !ok {
		return
	}
	rs, err := h.d.Store.ListPlaybookRuns(r.Context(), id, 50)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list runs")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"runs": rs, "count": len(rs)})
}

func (h *handler) runStatus(w http.ResponseWriter, r *http.Request) {
	runID, err := uuid.Parse(chi.URLParam(r, "runId"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad run id")
		return
	}
	rec, err := h.d.Store.GetPlaybookRun(r.Context(), runID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "run not found")
		return
	}
	// While running, the persisted output is empty; serve the live buffer so the
	// browser sees output stream in by polling.
	if out, live := h.svc.LiveOutput(runID); live {
		rec.Output = out
	}
	httpx.WriteJSON(w, http.StatusOK, rec)
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
