package vulnscan

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/msrc"
)

// Mount attaches vulnerability-scan routes. Running/viewing scans requires
// Host.Scan; managing the vulnerability database (grype) and the MSRC mapping
// requires System.Configure.
func Mount(r chi.Router, d *app.Deps, svc *Service, msrcSvc *msrc.Service) {
	h := &handler{d: d, svc: svc, msrc: msrcSvc}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Post("/vuln-scans", h.trigger)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/vuln-scans", h.list)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Delete("/vuln-scans/failed", h.clearFailed)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/vuln-scans/latest", h.latest)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/vuln-scans/db", h.dbStatus)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/vuln-scans/msrc", h.msrcStatus)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/vuln-scans/{id}", h.get)
		pr.With(d.Auth.RequirePermission("System.Configure")).Post("/vuln-scans/db/update", h.dbUpdate)
		pr.With(d.Auth.RequirePermission("System.Configure")).Post("/vuln-scans/db/import", h.dbImport)
		pr.With(d.Auth.RequirePermission("System.Configure")).Post("/vuln-scans/msrc/update", h.msrcUpdate)
		pr.With(d.Auth.RequirePermission("System.Configure")).Post("/vuln-scans/msrc/import", h.msrcImport)
	})
}

type handler struct {
	d    *app.Deps
	svc  *Service
	msrc *msrc.Service
}

// msrcStatus reports how much MSRC KB→CVE data is loaded.
func (h *handler) msrcStatus(w http.ResponseWriter, r *http.Request) {
	st, err := h.d.Store.MSRCStatus(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read MSRC status")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

// msrcUpdate fetches recent MSRC releases online and stores the mapping.
func (h *handler) msrcUpdate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	n, err := h.msrc.UpdateOnline(ctx)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "MSRC update failed: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"entries": n})
}

// msrcImport loads MSRC data from an uploaded offline bundle (zip of CVRF JSON, a
// JSON array of documents, or a single CVRF JSON document).
func (h *handler) msrcImport(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 256<<20))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "could not read body")
		return
	}
	n, err := h.msrc.Import(r.Context(), body)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "MSRC import failed: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"entries": n})
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
