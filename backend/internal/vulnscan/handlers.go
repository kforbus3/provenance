package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kforbus3/Moorgate/backend/internal/app"
	"github.com/kforbus3/Moorgate/backend/internal/auth"
	"github.com/kforbus3/Moorgate/backend/internal/httpx"
	"github.com/kforbus3/Moorgate/backend/internal/models"
	"github.com/kforbus3/Moorgate/backend/internal/msrc"
	"github.com/kforbus3/Moorgate/backend/internal/store"
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
		// Literal segments are registered before the {id} pattern so
		// /vuln-scans/latest/sbom resolves to the host lookup rather than being
		// read as a scan whose id is "latest".
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/vuln-scans/latest/sbom", h.latestSBOM)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/vuln-scans/{id}", h.get)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/vuln-scans/{id}/sbom", h.scanSBOMDownload)
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
	HostID  string   `json:"hostId"`
	GroupID string   `json:"groupId"`
	HostIDs []string `json:"hostIds"` // bulk: scan an ad-hoc selection of hosts
}

// trigger starts a scan for one host, an ad-hoc list of hosts, or every host in a
// group, returning the created scan ids.
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
	case len(rq.HostIDs) > 0:
		if len(rq.HostIDs) > 1000 {
			httpx.WriteError(w, http.StatusBadRequest, "too many hosts in one request")
			return
		}
		for _, s := range rq.HostIDs {
			id, err := uuid.Parse(s)
			if err != nil {
				httpx.WriteError(w, http.StatusBadRequest, "invalid host id: "+s)
				return
			}
			host, err := h.d.Store.GetHost(r.Context(), id)
			if err != nil {
				continue // skip hosts that vanished between selection and submit
			}
			hosts = append(hosts, host)
		}
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
		go h.svc.Run(context.WithoutCancel(r.Context()), scanID, host)
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
	classifyRemediation(r.Context(), h.d.Store, scan.HostID, findings)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"scan": scan, "findings": findings})
}

// classifyRemediation annotates each finding with how to fix it on the host —
// distinguishing an orphaned/obsolete package (remove it) from one an update fixes —
// by cross-referencing the host's obsolete-package and pending-update inventory.
// Best-effort: if the host or its inventory can't be loaded, findings are left
// unclassified rather than failing the request.
func classifyRemediation(ctx context.Context, st *store.Store, hostID uuid.UUID, findings []models.VulnFinding) {
	host, err := st.GetHost(ctx, hostID)
	if err != nil || host.Inventory == nil {
		return
	}
	obsolete, pending := map[string]bool{}, map[string]bool{}
	for _, p := range host.Inventory.ObsoletePackages {
		obsolete[p] = true
	}
	for _, u := range host.Inventory.UpdatePackages {
		pending[u.Package] = true
	}
	updatesKnown := host.Inventory.UpdatesCheckedAt != nil
	for i := range findings {
		findings[i].Remediation = models.ClassifyRemediation(findings[i], obsolete, pending, updatesKnown)
	}
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

// --- SBOM download ------------------------------------------------------

// writeSBOM serves a stored CycloneDX document as a download.
//
// The bytes are written back exactly as stored rather than re-marshalled: a
// consumer may have recorded the document's digest, and reordering JSON keys
// would break that for no benefit.
func writeSBOM(w http.ResponseWriter, b *store.VulnSBOM) {
	name := b.Hostname
	if name == "" {
		name = b.HostID.String()
	}
	filename := fmt.Sprintf("%s-%s-sbom.cdx.json",
		sanitizeFilename(name), b.CreatedAt.UTC().Format("20060102T150405Z"))

	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	// The component count is the one fact a caller may want without parsing the
	// body — a monitoring check asking "did this host produce an inventory".
	w.Header().Set("X-SBOM-Components", strconv.Itoa(b.Components))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b.Document)
}

// sanitizeFilename reduces a hostname to something safe in a Content-Disposition
// header. Hostnames come from enrollment and are not guaranteed to be tame; an
// unescaped quote or newline here would let a host name inject a header.
func sanitizeFilename(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "host"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return string(out)
}

// scanSBOMDownload returns the bill of materials captured by one scan.
func (h *handler) scanSBOMDownload(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid scan id")
		return
	}
	b, err := h.d.Store.GetVulnSBOM(r.Context(), id)
	if err != nil {
		// A scan that predates SBOM capture, failed before collection, or ran
		// against a host with neither dpkg nor rpm has no document. That is an
		// ordinary absence, not an error worth a 500.
		httpx.WriteError(w, http.StatusNotFound,
			"no SBOM for this scan (it may predate inventory capture, or the host has no supported package manager)")
		return
	}
	writeSBOM(w, b)
}

// latestSBOM returns a host's most recent bill of materials.
func (h *handler) latestSBOM(w http.ResponseWriter, r *http.Request) {
	hostID, err := uuid.Parse(r.URL.Query().Get("hostId"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "hostId query parameter is required")
		return
	}
	b, err := h.d.Store.LatestVulnSBOMForHost(r.Context(), hostID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound,
			"no SBOM for this host yet — run a vulnerability scan to collect one")
		return
	}
	writeSBOM(w, b)
}
