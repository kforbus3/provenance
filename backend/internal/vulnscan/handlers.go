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

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/msrc"
	"github.com/kforbus3/provenance/backend/internal/store"
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
		// Container image findings, keyed by digest. Provenance-global by nature: the
		// same digest is the same bytes everywhere, so this is one table the UI
		// joins against rather than a per-host payload repeated for every host
		// running a popular base image.
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/container-images", h.containerImages)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Post("/container-images/scan", h.scanContainerImages)
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

	// The scan outlives the request, so it needs a context that is not cancelled
	// with it -- and one that still knows which tenant it is for.
	//
	// This was context.WithoutCancel(context.Background()), which is just
	// context.Background(): a context with no values at all. Under multi-tenancy
	// that made vulnerability scanning fail completely and quietly. The scan row
	// was created on the REQUEST context, so it landed in the right tenant; the
	// scan itself ran, SSHed to the host and came back with findings; and then the
	// insert was refused:
	//
	//   store findings: ERROR: new row violates row-level security policy
	//   for table "vuln_findings" (SQLSTATE 42501)
	//
	// because vuln_findings.tenant_id defaults to prov_current_tenant(), and on a
	// context with no tenant that is nobody. Every manual scan on a multi-tenant
	// instance ended as "failed" with no findings stored, and nothing in the
	// message pointed at tenancy.
	//
	// TenantScope is the idiom already used for detached work elsewhere (see the
	// terminal's disconnect callback): a background context, explicitly scoped to
	// the tenant this request is acting for, rather than the request's whole value
	// set carried into a goroutine that outlives it.
	bg := h.d.Auth.TenantScope(context.Background(), p)

	ids := []string{}
	for _, host := range hosts {
		scanID, err := h.d.Store.CreateVulnScan(r.Context(), host.ID, &p.UserID, p.Username, false)
		if err != nil {
			continue
		}
		ids = append(ids, scanID.String())
		// Bounded, like every other fan-out in this codebase and unlike this one
		// until now. A scan SSHes to the host and then calls the grype sidecar,
		// so "scan this group" on 500 hosts meant 500 simultaneous dials through
		// a jump host whose sshd starts refusing connections at MaxStartups 10 --
		// the same failure the monitor's own fan-out limit exists to avoid, and
		// which its comment records having caused once already.
		//
		// The scheduled path was already bounded at scanFanoutLimit. Only the
		// path a person triggers from the UI was not, which is the one most
		// likely to be pointed at the whole fleet at once.
		go func(hst *models.Host, id uuid.UUID) {
			scanSem <- struct{}{}
			defer func() { <-scanSem }()
			h.svc.Run(bg, id, hst)
		}(host, scanID)
	}
	h.audit(r, "vuln_scan.start", map[string]any{"hosts": len(ids)})
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"scanIds": ids})
}

// scanSem bounds how many manual scans run at once, across all requests. Package
// level on purpose: a per-request semaphore would let ten operators each start
// their own burst and reproduce exactly what this prevents.
var scanSem = make(chan struct{}, 8)

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
	// Both annotations come from the host's inventory, so it is read once. The
	// running kernel is what makes kernel findings readable: grype attributes them to
	// whichever userspace helper shares the kernel's source package (see
	// models.IsKernelSourceFinding), matched at THAT package's version — which is not
	// necessarily the kernel the host booted.
	kernel := annotateFindings(r.Context(), h.d.Store, scan.HostID, findings)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"scan": scan, "findings": findings, "kernelRelease": kernel,
	})
}

// annotateFindings classifies HOW to fix each finding on the host — distinguishing
// an orphaned/obsolete package (remove it) from one an update fixes — by
// cross-referencing the host's obsolete-package and pending-update inventory, and
// returns the host's running kernel release.
//
// Best-effort: if the host or its inventory can't be loaded, findings are left
// unclassified and the kernel release is empty rather than failing the request.
func annotateFindings(ctx context.Context, st *store.Store, hostID uuid.UUID, findings []models.VulnFinding) string {
	host, err := st.GetHost(ctx, hostID)
	if err != nil || host.Inventory == nil {
		return ""
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
	return host.Inventory.KernelVersion
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

// containerImages returns what is known about every scanned container image.
//
// Whole-table rather than per-host: the set is bounded by the number of distinct
// images the fleet runs, which is small, and a host page needs the results for
// whatever it happens to be running without a round trip per container.
func (h *handler) containerImages(w http.ResponseWriter, r *http.Request) {
	refs, err := h.d.Store.DistinctContainerImages(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list container images")
		return
	}
	digests := make([]string, 0, len(refs))
	for _, ref := range refs {
		digests = append(digests, ref.Digest)
	}
	scans, err := h.d.Store.ContainerImageScans(r.Context(), digests)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read image scans")
		return
	}
	out := make([]any, 0, len(refs))
	for _, ref := range refs {
		if sc, ok := scans[ref.Digest]; ok {
			out = append(out, sc)
			continue
		}
		// Known to be running, not yet scanned. Reported as such rather than
		// omitted: "we have not looked at this yet" is a different statement from
		// "this image is clean", and a UI that cannot tell them apart will show
		// the reassuring one.
		out = append(out, map[string]any{
			"digest": ref.Digest, "image": ref.Image, "pending": true,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"images": out})
}

// scanContainerImages runs a scan pass now rather than waiting for the daily one.
func (h *handler) scanContainerImages(w http.ResponseWriter, r *http.Request) {
	// Detached, because this is a sweep of every image the fleet runs and each one
	// is a grype run of tens of seconds. On the request's own context it could not
	// finish: every route is behind middleware.Timeout(60s), so a fleet of any size
	// had its remaining results thrown away with
	//
	//   "container scan: saving result" err="context deadline exceeded"
	//
	// once the minute was up -- images scanned, bytes read, findings computed, and
	// then dropped on the floor, with the caller getting no answer either.
	//
	// The tenant does not matter for these particular rows (container_image_scans
	// is Provenance-global: the same digest is the same bytes for everybody, and
	// the table carries no tenant_id), but the scope is set anyway so this does not
	// become the next thing that quietly writes nothing if that ever changes.
	ctx, cancel := context.WithTimeout(
		h.d.Auth.TenantScope(context.Background(), auth.MustPrincipal(r)), 2*time.Hour)
	h.audit(r, "vuln_scan.container_images", map[string]any{"started": true})
	go func() {
		defer cancel()
		scanned, failed := h.svc.ScanContainerImages(ctx)
		h.d.Log.Info("container image scan finished", "scanned", scanned, "failed", failed)
	}()
	// Accepted, not done: the caller polls /container-images for results, which is
	// what the scheduled sweep has always left behind too.
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"started": true})
}
