package vulnscan

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
)

// Mount attaches vulnerability-scan routes. Running/viewing scans requires
// Host.Scan; managing the vulnerability database requires System.Configure.
func Mount(r chi.Router, d *app.Deps, svc *Service) {
	h := &handler{d: d, svc: svc}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Post("/vuln-scans", h.trigger)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/vuln-scans", h.list)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Delete("/vuln-scans/failed", h.clearFailed)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/vuln-scans/latest", h.latest)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/vuln-scans/db", h.dbStatus)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/vuln-scans/{id}", h.get)
		pr.With(d.Auth.RequirePermission("System.Configure")).Post("/vuln-scans/db/update", h.dbUpdate)
		pr.With(d.Auth.RequirePermission("System.Configure")).Post("/vuln-scans/db/import", h.dbImport)
	})
}

type handler struct {
	d   *app.Deps
	svc *Service
}

type triggerReq struct {
	HostID  string `json:"hostId"`
	GroupID string `json:"groupId"`
}

// trigger starts a scan for one host or every host in a group, returning the
// created scan ids.
func (h *handler) trigger(w http.ResponseWriter, r *http.Request) {
	var rq triggerReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := auth.MustPrincipal(r)
	var hosts []*models.Host
	switch {
	case rq.HostID != "":
		id, err := uuid.Parse(rq.HostID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
			return
		}
		host, err := h.d.Store.GetHost(r.Context(), id)
		if err != nil {
			httpx.WriteError(w, http.StatusNotFound, "no such host")
			return
		}
		hosts = []*models.Host{host}
	case rq.GroupID != "":
		id, err := uuid.Parse(rq.GroupID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid group id")
			return
		}
		members, err := h.d.Store.HostsInGroup(r.Context(), id)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not resolve group")
			return
		}
		for i := range members {
			hosts = append(hosts, &members[i])
		}
	default:
		httpx.WriteError(w, http.StatusBadRequest, "hostId or groupId is required")
		return
	}
	if len(hosts) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "no hosts to scan")
		return
	}

	ids := []string{}
	for _, host := range hosts {
		scanID, err := h.d.Store.CreateVulnScan(r.Context(), host.ID, &p.UserID, p.Username, false)
		if err != nil {
			continue
		}
		ids = append(ids, scanID.String())
		go h.svc.Run(scanID, host)
	}
	h.audit(r, "vuln_scan.start", map[string]any{"hosts": len(ids)})
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"scanIds": ids})
}

// clearFailed removes failed scan records (error-only rows with no findings),
// clearing the "recent failures" surface.
func (h *handler) clearFailed(w http.ResponseWriter, r *http.Request) {
	n, err := h.d.Store.DeleteFailedVulnScans(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not clear failed scans")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": n})
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	var hostID *uuid.UUID
	if v := r.URL.Query().Get("hostId"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			hostID = &id
		}
	}
	scans, err := h.d.Store.ListVulnScans(r.Context(), hostID, 50)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list scans")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"scans": scans})
}

func (h *handler) latest(w http.ResponseWriter, r *http.Request) {
	scans, err := h.d.Store.LatestVulnScans(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not build roll-up")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"scans": scans})
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	scan, err := h.d.Store.GetVulnScan(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such scan")
		return
	}
	findings, err := h.d.Store.GetVulnFindings(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not load findings")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"scan": scan, "findings": findings})
}

func (h *handler) dbStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.svc.DBStatus(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "scanner unreachable")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": status})
}

func (h *handler) dbUpdate(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.DBUpdate(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	h.audit(r, "vuln_scan.db_update", nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"output": out})
}

func (h *handler) dbImport(w http.ResponseWriter, r *http.Request) {
	// Stream the uploaded archive straight to the sidecar (can be ~1GB).
	body := http.MaxBytesReader(w, r.Body, 2<<30)
	out, err := h.svc.DBImport(r.Context(), body)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "vuln_scan.db_import", nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"output": out})
}

func (h *handler) audit(r *http.Request, action string, detail map[string]any) {
	p := auth.MustPrincipal(r)
	if detail == nil {
		detail = map[string]any{}
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: action, TargetKind: "vuln_scan", Detail: detail,
	})
}
