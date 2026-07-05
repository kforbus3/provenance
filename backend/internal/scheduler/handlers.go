package scheduler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
)

// Mount attaches schedule routes (Schedule.Manage, admin-only by default).
func Mount(r chi.Router, d *app.Deps, eng *Engine) {
	h := &handler{d: d, eng: eng}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		// The display timezone affects every timestamp in the UI, so any signed-in
		// user can read it; only System.Configure can change it.
		pr.Get("/timezone", h.getTimezone)
		pr.With(d.Auth.RequirePermission("System.Configure")).Put("/timezone", h.putTimezone)
		pr.With(d.Auth.RequirePermission("Schedule.Manage")).Get("/schedules", h.list)
		pr.With(d.Auth.RequirePermission("Schedule.Manage")).Post("/schedules", h.create)
		pr.With(d.Auth.RequirePermission("Schedule.Manage")).Put("/schedules/{id}", h.update)
		pr.With(d.Auth.RequirePermission("Schedule.Manage")).Delete("/schedules/{id}", h.delete)
		pr.With(d.Auth.RequirePermission("Schedule.Manage")).Post("/schedules/{id}/enable", h.enable)
		pr.With(d.Auth.RequirePermission("Schedule.Manage")).Post("/schedules/{id}/run", h.runNow)
	})
}

type handler struct {
	d   *app.Deps
	eng *Engine
}

type scheduleReq struct {
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	Enabled    bool              `json:"enabled"`
	TargetKind string            `json:"targetKind"`
	TargetID   string            `json:"targetId"`
	Recurrence models.Recurrence `json:"recurrence"`
	Payload    json.RawMessage   `json:"payload"`
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	items, err := h.d.Store.ListSchedules(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list schedules")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"schedules": items, "count": len(items)})
}

// resolve validates the target and returns its display name + kind.
func (h *handler) toModel(r *http.Request, rq *scheduleReq) (*models.Schedule, string, bool) {
	rq.Name = strings.TrimSpace(rq.Name)
	if rq.Name == "" {
		return nil, "name is required", false
	}
	if rq.Kind != "scan" && rq.Kind != "playbook" {
		return nil, "kind must be scan or playbook", false
	}
	if rq.TargetKind == "" {
		rq.TargetKind = "host"
	}
	tid, err := uuid.Parse(rq.TargetID)
	if err != nil {
		return nil, "bad target id", false
	}
	var targetName string
	if rq.TargetKind == "group" {
		g, err := h.d.Store.GetGroup(r.Context(), tid)
		if err != nil {
			return nil, "group not found", false
		}
		targetName = g.Name
	} else {
		host, err := h.d.Store.GetHost(r.Context(), tid)
		if err != nil {
			return nil, "host not found", false
		}
		targetName = host.Hostname
	}
	return &models.Schedule{
		Name: rq.Name, Kind: rq.Kind, Enabled: rq.Enabled, TargetKind: rq.TargetKind,
		TargetID: &tid, TargetName: targetName, Recurrence: rq.Recurrence, Payload: rq.Payload,
	}, "", true
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var rq scheduleReq
	if !httpx.Decode(w, r, &rq) {
		return
	}
	m, msg, ok := h.toModel(r, &rq)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	p := auth.MustPrincipal(r)
	m.Requester = p.Username
	sc, err := h.d.Store.CreateSchedule(r.Context(), m, &p.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create schedule")
		return
	}
	h.audit(r, "schedule.create", sc.ID.String(), map[string]any{"name": sc.Name, "kind": sc.Kind})
	httpx.WriteJSON(w, http.StatusCreated, sc)
}

func (h *handler) update(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseID(w, r)
	if !ok {
		return
	}
	var rq scheduleReq
	if !httpx.Decode(w, r, &rq) {
		return
	}
	m, msg, ok := h.toModel(r, &rq)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	sc, err := h.d.Store.UpdateSchedule(r.Context(), id, m)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "schedule not found")
		return
	}
	h.audit(r, "schedule.update", sc.ID.String(), map[string]any{"name": sc.Name})
	httpx.WriteJSON(w, http.StatusOK, sc)
}

func (h *handler) delete(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseID(w, r)
	if !ok {
		return
	}
	if err := h.d.Store.DeleteSchedule(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "schedule not found")
		return
	}
	h.audit(r, "schedule.delete", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (h *handler) enable(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseID(w, r)
	if !ok {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if !httpx.Decode(w, r, &body) {
		return
	}
	sc, err := h.d.Store.SetScheduleEnabled(r.Context(), id, body.Enabled)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "schedule not found")
		return
	}
	h.audit(r, "schedule.enable", id.String(), map[string]any{"enabled": body.Enabled})
	httpx.WriteJSON(w, http.StatusOK, sc)
}

func (h *handler) getTimezone(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"timezone": h.d.Store.DisplayTimezone(r.Context())})
}

func (h *handler) putTimezone(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Timezone string `json:"timezone"`
	}
	if !httpx.Decode(w, r, &body) {
		return
	}
	// Validate against the IANA database (empty = use the server default).
	if body.Timezone != "" {
		if _, err := time.LoadLocation(body.Timezone); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "unknown timezone")
			return
		}
	}
	if err := h.d.Store.SetSetting(r.Context(), "timezone", map[string]string{"timezone": body.Timezone}); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save timezone")
		return
	}
	// Existing schedules' next-run times were computed in the old zone; refresh.
	if err := h.d.Store.RecomputeEnabledNextRuns(r.Context()); err != nil {
		h.d.Log.Warn("recompute schedules after timezone change", "err", err)
	}
	h.audit(r, "system.timezone", "", map[string]any{"timezone": body.Timezone})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"timezone": body.Timezone})
}

func (h *handler) runNow(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseID(w, r)
	if !ok {
		return
	}
	sc, err := h.d.Store.GetSchedule(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "schedule not found")
		return
	}
	status := h.eng.Fire(r.Context(), sc)
	// Record the manual run so the Schedules table's "Last" column reflects it;
	// next_run_at is left untouched so the recurring cadence is undisturbed.
	if err := h.d.Store.MarkScheduleRun(r.Context(), id, time.Now(), status); err != nil {
		h.d.Log.Warn("mark manual schedule run", "schedule", id, "err", err)
	}
	h.audit(r, "schedule.run", id.String(), map[string]any{"name": sc.Name, "status": status})
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"status": status})
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
		TargetKind: "schedule", TargetID: targetID, Detail: detail,
	})
}
