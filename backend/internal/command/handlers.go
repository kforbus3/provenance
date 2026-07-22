package command

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/accesspolicy"
	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

// Mount attaches ad-hoc command routes, gated by Command.Run (admin-only by
// default) plus per-host access. Governed by the command-control policy at run time.
func Mount(r chi.Router, d *app.Deps, svc *Service) {
	h := &handler{d: d, svc: svc}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("Command.Run")).Post("/commands/run", h.run)
		pr.With(d.Auth.RequirePermission("Command.Run")).Get("/command-runs", h.runs)
		pr.With(d.Auth.RequirePermission("Command.Run")).Get("/command-runs/{runId}", h.runStatus)
	})
}

type handler struct {
	d   *app.Deps
	svc *Service
}

type runReq struct {
	Command    string   `json:"command"`
	TargetKind string   `json:"targetKind"` // host | group
	HostIDs    []string `json:"hostIds"`
	GroupID    string   `json:"groupId"`
}

func (h *handler) run(w http.ResponseWriter, r *http.Request) {
	var rq runReq
	if !httpx.Decode(w, r, &rq) {
		return
	}
	rq.Command = strings.TrimSpace(rq.Command)
	if rq.Command == "" {
		httpx.WriteError(w, http.StatusBadRequest, "command is required")
		return
	}
	if rq.TargetKind == "" {
		rq.TargetKind = "host"
	}
	p := auth.MustPrincipal(r)

	var (
		hosts      []*models.Host
		targetName string
		targetID   *uuid.UUID
	)
	switch rq.TargetKind {
	case "host":
		if len(rq.HostIDs) == 0 {
			httpx.WriteError(w, http.StatusBadRequest, "no target hosts")
			return
		}
		seen := map[uuid.UUID]bool{}
		for _, raw := range rq.HostIDs {
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
			if host.Protocol == "rdp" {
				httpx.WriteError(w, http.StatusBadRequest, host.Hostname+" is a Windows host (use PowerShell scripts)")
				return
			}
			if !h.canAccessHost(r, p, host.ID) {
				httpx.WriteError(w, http.StatusForbidden, "not authorized for host "+host.Hostname)
				return
			}
			if dec := h.d.AccessPolicy.Authorize(r.Context(), connCtx(r, p, host)); dec.Denied {
				httpx.WriteError(w, http.StatusForbidden, dec.Reason)
				return
			}
			hosts = append(hosts, host)
		}
		if len(hosts) == 1 {
			targetName = hosts[0].Hostname
			targetID = &hosts[0].ID
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
		for i := range members {
			m := members[i]
			if m.Protocol != "rdp" && h.canAccessHost(r, p, m.ID) &&
				!h.d.AccessPolicy.Authorize(r.Context(), connCtx(r, p, &m)).Denied {
				hosts = append(hosts, &m)
			}
		}
		if len(hosts) == 0 {
			httpx.WriteError(w, http.StatusForbidden, "no Linux hosts in this group are accessible to you")
			return
		}
		targetName = g.Name
		targetID = &g.ID

	default:
		httpx.WriteError(w, http.StatusBadRequest, "unknown target kind")
		return
	}

	rec, err := h.d.Store.CreateCommandRun(r.Context(), store.CommandRun{
		Command:    rq.Command,
		Requester:  p.Username,
		TargetKind: rq.TargetKind,
		TargetID:   targetID,
		TargetName: targetName,
		HostCount:  len(hosts),
	}, &p.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create run")
		return
	}
	go h.svc.Run(rec.ID, rq.Command, hosts, p.UserID, p.Username)

	names := make([]string, 0, len(hosts))
	for _, hh := range hosts {
		names = append(names, hh.Hostname)
	}
	h.audit(r, "command.run", rec.ID.String(), map[string]any{
		"command": rq.Command, "targetKind": rq.TargetKind, "target": targetName,
		"hosts": names, "hostCount": len(hosts),
	})
	httpx.WriteJSON(w, http.StatusAccepted, rec)
}

func (h *handler) runs(w http.ResponseWriter, r *http.Request) {
	rs, err := h.d.Store.ListCommandRuns(r.Context(), 50)
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
	rec, err := h.d.Store.GetCommandRun(r.Context(), runID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "run not found")
		return
	}
	if out, live := h.svc.LiveOutput(runID); live {
		rec.Output = out
	}
	httpx.WriteJSON(w, http.StatusOK, rec)
}

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

// connCtx builds the ABAC evaluation context for a command target.
func connCtx(r *http.Request, p *auth.Principal, host *models.Host) accesspolicy.ConnCtx {
	return accesspolicy.ConnCtx{
		UserID: p.UserID, Username: p.Username, IsSuper: p.IsSuperAdmin,
		HostID: host.ID, HostName: host.Hostname, Environment: host.Environment,
		Tags: host.Tags, Protocol: host.Protocol, Surface: "command", IP: accesspolicy.RequestIP(r),
	}
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
		TargetKind: "command_run", TargetID: targetID, Detail: detail,
	})
}
