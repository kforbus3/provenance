package stacks

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

type handler struct {
	d   *app.Deps
	svc *Service
}

// Mount attaches container-stack routes.
//
// Reading a stack needs Host.View -- it is part of a host's description. CHANGING
// one needs Host.Edit, and DEPLOYING one needs Command.Run: writing a file to a
// host and bringing containers up is running something on that host, and it would
// be strange for the permission that governs running a command not to govern the
// one path that runs several.
func Mount(r chi.Router, d *app.Deps, svc *Service) {
	h := &handler{d: d, svc: svc}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("Host.View")).Get("/stacks", h.list)
		pr.With(d.Auth.RequirePermission("Host.View")).Get("/stacks/{id}", h.get)
		pr.With(d.Auth.RequirePermission("Host.View")).Get("/stacks/{id}/history", h.history)
		pr.With(d.Auth.RequirePermission("Host.View")).Get("/stacks/drift", h.drift)
		// What exists on the fleet, whether or not Provenance manages it. No setup:
		// every compose-managed container records its own project and directory.
		pr.With(d.Auth.RequirePermission("Host.View")).Get("/stacks/discovered", h.discovered)
		// Containers the fleet reports as not doing their job, fleet-wide. Not
		// under a stack id: the whole point is the question nobody could ask
		// before, which is "is anything wrong anywhere".
		pr.With(d.Auth.RequirePermission("Host.View")).Get("/stacks/unhealthy", h.unhealthy)
		pr.With(d.Auth.RequirePermission("Host.Edit")).Post("/stacks", h.save)
		pr.With(d.Auth.RequirePermission("Host.Edit")).Delete("/stacks/{id}", h.del)
		pr.With(d.Auth.RequirePermission("Command.Run")).Post("/stacks/{id}/deploy", h.deploy)
		pr.With(d.Auth.RequirePermission("Command.Run")).Post("/stacks/{id}/rollback", h.rollback)
	})
}

func (h *handler) unhealthy(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.store.UnhealthyContainers(r.Context())
	if err != nil {
		h.d.Log.Warn("listing unhealthy containers", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not list container health")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"containers": out})
}

func (h *handler) discovered(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.store.DiscoveredProjects(r.Context())
	if err != nil {
		h.d.Log.Warn("listing discovered compose projects", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not list compose projects")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"projects": out})
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	var hostID *uuid.UUID
	if q := r.URL.Query().Get("hostId"); q != "" {
		id, err := uuid.Parse(q)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid hostId")
			return
		}
		hostID = &id
	}
	out, err := h.svc.store.ListStacks(r.Context(), hostID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list stacks")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"stacks": out})
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	st, err := h.svc.store.GetStack(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such stack")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (h *handler) history(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	revs, err := h.svc.store.StackHistory(r.Context(), id, 50)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read history")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"revisions": revs})
}

func (h *handler) drift(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.Drift(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not compute drift")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"stacks": out})
}

type saveReq struct {
	HostID  string `json:"hostId"`
	Name    string `json:"name"`
	Compose string `json:"compose"`
	Path    string `json:"path"`
	Note    string `json:"note"`
}

// save records a definition. It does NOT deploy it.
//
// Saving and deploying are separate calls because they are separate decisions:
// editing a compose file should not restart somebody's database because the
// editor happened to hit save. It also leaves room for the approval and staged
// rollout that govern the deploy.
func (h *handler) save(w http.ResponseWriter, r *http.Request) {
	var rq saveReq
	if !httpx.Decode(w, r, &rq) {
		return
	}
	hostID, err := uuid.Parse(strings.TrimSpace(rq.HostID))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "a valid hostId is required")
		return
	}
	p := auth.MustPrincipal(r)
	st, err := h.svc.store.UpsertStack(r.Context(), store.StackInput{
		HostID: hostID, Name: strings.TrimSpace(rq.Name), Compose: rq.Compose,
		Path: strings.TrimSpace(rq.Path), Note: strings.TrimSpace(rq.Note),
		AuthorID: &p.UserID, AuthorName: p.Username,
	})
	if err != nil {
		if err == store.ErrInvalidStackName {
			httpx.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "could not save the stack")
		return
	}
	h.audit(r, "stack.save", st.ID.String(), map[string]any{
		"host": st.Hostname, "name": st.Name, "revision": st.Revision})
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (h *handler) del(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	st, err := h.svc.store.GetStack(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such stack")
		return
	}
	if err := h.svc.store.DeleteStack(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete the stack")
		return
	}
	h.audit(r, "stack.delete", id.String(), map[string]any{"host": st.Hostname, "name": st.Name})
	// Said plainly, because the alternative reading is dangerous: this forgets the
	// definition and leaves the containers running.
	httpx.WriteJSON(w, http.StatusOK, map[string]string{
		"status": "deleted",
		"note":   "the definition was removed; the containers on " + st.Hostname + " are still running",
	})
}

func (h *handler) deploy(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	// Detached from the request, and answered immediately.
	//
	// A deploy pulls images, and eight of them takes minutes. Every route is
	// behind middleware.Timeout(60s), so this ran on the request context, was
	// cancelled mid-pull, and then could not even record what had happened --
	// "recording stack deployment: context canceled". The screen went on showing
	// the previous outcome, so pressing Deploy looked like it had done nothing,
	// which is exactly what it had done.
	//
	// Same treatment as the registry check, for the same reason: work that
	// outlasts a request must not be tied to one.
	ctx := context.WithoutCancel(r.Context())

	// The stateful-image refusal is answered ON the request, before anything is
	// detached, because a deploy that reports back asynchronously cannot ask a
	// question. See Service.PreflightStatefulMajor.
	waive := Waivers{
		StatefulMajor: r.URL.Query().Get("acknowledgeStatefulMajor") == "1",
		AlreadyFailed: r.URL.Query().Get("acknowledgeFailedRevision") == "1",
	}
	if refusal := h.svc.Preflight(ctx, id, waive); refusal != nil {
		httpx.WriteJSON(w, http.StatusConflict, refusal)
		return
	}
	// Captured here, not in the goroutine: the actor belongs to the request, and
	// reading it after the handler has returned is a race waiting to be found.
	actor := auth.MustPrincipal(r)
	go func() {
		var (
			st  *store.ContainerStack
			out string
			err error
		)
		st, out, err = h.svc.DeployWaiving(ctx, id, waive)
		if err != nil {
			detail := map[string]any{"output": out}
			if st != nil {
				detail["host"] = st.Hostname
				detail["name"] = st.Name
			}
			h.d.Log.Warn("stack deploy failed", "stack", id, "err", err)
			h.auditAs(ctx, actor, "stack.deploy_failed", id.String(), detail)
			return
		}
		detail := map[string]any{"host": st.Hostname, "name": st.Name, "revision": st.Revision}
		// A waived guard is a decision, and the only place it can be read back from
		// afterwards is here.
		if waive.StatefulMajor {
			detail["statefulMajorAcknowledged"] = true
		}
		if waive.AlreadyFailed {
			detail["failedRevisionAcknowledged"] = true
		}
		h.auditAs(ctx, actor, "stack.deploy", id.String(), detail)
	}()

	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"status": "deploying",
		"note":   "pulling and recreating; the stack row shows the outcome when it finishes",
	})
}

func (h *handler) rollback(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	out, err := h.svc.Rollback(r.Context(), id)
	if err != nil {
		h.audit(r, "stack.rollback_failed", id.String(), map[string]any{"output": out})
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	h.audit(r, "stack.rollback", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "rolled_back", "output": out})
}

func parseID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid stack id")
		return uuid.Nil, false
	}
	return id, true
}

func (h *handler) audit(r *http.Request, action, target string, detail map[string]any) {
	h.auditAs(r.Context(), auth.MustPrincipal(r), action, target, detail)
}

// auditAs records an event for work that outlives its request. The actor is
// passed in rather than read from the request, which by then may be over.
func (h *handler) auditAs(ctx context.Context, p *auth.Principal, action, target string, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	_, _ = h.d.Store.AppendAudit(ctx, models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: action,
		TargetKind: "stack", TargetID: target, Detail: detail,
	})
}
